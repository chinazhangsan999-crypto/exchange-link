# 联盟代码隔离域

该域名目前故意只返回 404，用于确保不可信联盟 JavaScript 不会与公共前台或后台共享 Origin、Cookie 或本地存储。

若需要真正嵌入第三方代码，必须先获得产品层对 sandbox iframe 的明确许可；没有该隔离边界，不能安全地在页面中运行任意第三方 JavaScript。
