'use strict';

const crypto = require('crypto');
const PartnerModel = require('../models/PartnerModel');
const SourceTokenModel = require('../models/SourceTokenModel');
const LogModel = require('../models/LogModel');
const SystemModel = require('../models/SystemModel');
const FrontendOriginModel = require('../models/FrontendOriginModel');
const { isPartnerVisitRateLimited } = require('../middlewares/rateLimit');
const { parseHostname, matchesPartnerDomain, normalizeRegisteredDomain } = require('../utils/network');

const CLAIM_TTL_SECONDS = 15 * 60;
const INVALID_USER_AGENT = /curl|python|requests|headlesschrome|postman|wget|httpclient|scrapy|bot|spider|crawl|slurp/i;

async function resolveSourceAttribution({ sourceSidPresent = false, sourceSid = '', referer = '' } = {}) {
  const observedDomain = normalizeRegisteredDomain(parseHostname(referer));
  const [sidBinding, candidates] = await Promise.all([
    sourceSidPresent ? SourceTokenModel.findActiveSid(sourceSid) : Promise.resolve(null),
    PartnerModel.listInflowCandidates()
  ]);
  const domainPartner = observedDomain
    ? candidates.find(item => normalizeRegisteredDomain(item.domain) === observedDomain)
    : null;

  let partnerId = null;
  let method = 'unattributed';
  if (domainPartner) {
    partnerId = domainPartner.id;
    if (!sourceSidPresent) method = 'domain_only';
    else if (!sidBinding) method = 'invalid_sid_domain_match';
    else if (Number(sidBinding.partner_id) === Number(domainPartner.id)) method = 'sid_domain_match';
    else method = 'sid_domain_mismatch';
  } else if (sidBinding) {
    partnerId = sidBinding.partner_id;
    method = observedDomain ? 'sid_fallback_unknown_domain' : 'sid_fallback_no_referer';
  } else if (sourceSidPresent) {
    method = observedDomain ? 'invalid_sid_unknown_domain' : 'invalid_sid_no_referer';
  }

  return {
    partnerId,
    sourceTokenId: sidBinding?.token_id || null,
    sidPartnerId: sidBinding?.partner_id || null,
    domainPartnerId: domainPartner?.id || null,
    method,
    observedDomain,
    referer: String(referer || '')
  };
}

async function listOwnOrigins(frontendOrigin = '') {
  const values = new Set();
  const configuredSiteUrl = await SystemModel.configValue('site_url');
  for (const value of [configuredSiteUrl, frontendOrigin]) {
    try { values.add(new URL(String(value || '')).origin); } catch { /* 忽略空配置。 */ }
  }
  try {
    const rows = await FrontendOriginModel.listEnabledOrigins();
    for (const row of rows) {
      try { values.add(new URL(row.origin).origin); } catch { /* 数据已在写入时校验。 */ }
    }
  } catch {
    // 兼容尚未执行新迁移的测试/启动阶段，现有单体入口仍以 site_url 判断本站来源。
  }
  return [...values];
}

function isOwnReferer(refererUrl, ownOrigins) {
  const sourceHost = parseHostname(refererUrl.href);
  const localHosts = new Set(['localhost', '127.0.0.1', '::1']);
  return ownOrigins.some(value => {
    let ownUrl;
    try { ownUrl = new URL(value); } catch { return false; }
    const ownHost = parseHostname(ownUrl.href);
    if (!matchesPartnerDomain(sourceHost, ownHost)) return false;
    return !(localHosts.has(sourceHost) && sourceHost === ownHost && refererUrl.port !== ownUrl.port);
  });
}

function rejected(reasonCode, reasonText, extra = {}) {
  return {
    status: 'rejected',
    stage: extra.stage || 'source_resolution',
    visitorType: extra.visitorType || 'source_validation',
    classification: extra.classification || 'rejected',
    reasonCode,
    reasonText,
    ...extra
  };
}

async function prepareLanding({
  clientIp,
  userAgent,
  visitorHash = '',
  referer = '',
  sourceSidPresent = false,
  sourceSid = '',
  requestPath = '/',
  frontendOrigin = '',
  preResolvedSource = null
} = {}) {
  const ua = String(userAgent || '').trim();
  const rawReferer = String(referer || '').trim();
  if (!clientIp) return rejected('missing_client_ip', '无法识别客户端 IP');
  if (!ua || INVALID_USER_AGENT.test(ua)) {
    return rejected('abnormal_user_agent', '爬虫、无头浏览器或异常 User-Agent', { referer: rawReferer });
  }

  let source = preResolvedSource ? {
    ...preResolvedSource,
    referer: String(preResolvedSource.referer || rawReferer)
  } : null;

  if (!source) {
    if (!sourceSidPresent) {
      let refererUrl;
      try { refererUrl = new URL(rawReferer); } catch {
        return rejected(rawReferer ? 'invalid_referer' : 'direct_no_source',
          rawReferer ? 'Referer 格式无效' : '普通直访，未携带 SID 或 Referer', {
            referer: rawReferer,
            visitorType: rawReferer ? 'source_validation' : 'ordinary_direct'
          });
      }
      if (!/^https?:$/.test(refererUrl.protocol)) {
        return rejected('invalid_referer_protocol', 'Referer 协议不合法', { referer: rawReferer });
      }
      if (isOwnReferer(refererUrl, await listOwnOrigins(frontendOrigin))) {
        return { status: 'ignored', reasonCode: 'internal_navigation' };
      }
    }

    source = await resolveSourceAttribution({ sourceSidPresent, sourceSid, referer: rawReferer });
    if (!source.partnerId) {
      if (sourceSidPresent) {
        return rejected('invalid_sid', 'SID 不存在、已失效或无法归属到友链', {
          referer: rawReferer,
          observedDomain: source.observedDomain,
          sourceTokenId: source.sourceTokenId,
          attributionMethod: source.method,
          stage: 'sid_resolution'
        });
      }
      return rejected('unregistered_source_domain', '来源域名未登记，无法归属到友链', {
        referer: rawReferer,
        observedDomain: source.observedDomain
      });
    }
  }

  const partner = (await PartnerModel.listInflowCandidates())
    .find(item => Number(item.id) === Number(source.partnerId));
  if (!partner) {
    return rejected('unregistered_source_domain', '来源站点不存在或已不再接受归属', {
      referer: source.referer,
      observedDomain: source.observedDomain,
      partnerId: source.partnerId,
      sourceTokenId: source.sourceTokenId,
      attributionMethod: source.method
    });
  }

  const attemptId = crypto.randomUUID();
  if (isPartnerVisitRateLimited(partner.id, clientIp)) {
    return rejected('entry_cooldown', '重复请求已抑制（不影响此前已领取的有效凭证）', {
      referer: source.referer,
      observedDomain: source.observedDomain,
      partnerId: partner.id,
      sourceTokenId: source.sourceTokenId,
      attributionMethod: source.method || 'domain_only',
      attemptId,
      classification: 'suppressed',
      stage: 'claim_issue'
    });
  }

  const token = crypto.randomBytes(24).toString('base64url');
  await LogModel.createClaimToken({
    tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
    partnerId: partner.id,
    ip: clientIp,
    ttlSeconds: CLAIM_TTL_SECONDS,
    startedAtMs: Date.now(),
    referer: source.referer,
    sourceTokenId: source.sourceTokenId || null,
    sidPartnerId: source.sidPartnerId || null,
    domainPartnerId: source.domainPartnerId || (preResolvedSource ? null : partner.id),
    attributionMethod: source.method || 'domain_only',
    observedDomain: source.observedDomain,
    userAgent: ua,
    visitorHash,
    requestPath,
    attemptId
  });

  return { status: 'claim_issued', token, partnerId: partner.id, source, attemptId };
}

module.exports = { CLAIM_TTL_SECONDS, resolveSourceAttribution, prepareLanding };
