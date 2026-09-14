// 生产前台与测试前台复用同一套可信边缘代理逻辑，避免两套代码漂移。
import worker from '../public-edge/worker.js';

export default worker;
