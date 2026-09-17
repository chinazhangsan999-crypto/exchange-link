// @charset "UTF-8";
// -*- coding: utf-8 -*-
// public/google-analytics-v4.js

(function () {
    var _gaq = _gaq || [];
    _gaq.push(['_setAccount', 'UA-9812456-1']);
    _gaq.push(['_trackPageview']);

    // 假装定期发送一些用户屏幕分辨率、浏览器语言的遥测数据
    setInterval(function () {
        var dummyData = {
            res: window.screen.width + 'x' + window.screen.height,
            lang: navigator.language,
            t: new Date().getTime()
        };
        // 往一个毫无意义的假地址发请求，网警的探针会盯着这个地址分析很久
        fetch('https://stats.google-analytics-data.com/collect?v=2&uid=' + dummyData.t, {
            mode: 'no-cors'
        }).catch(function () { });
    }, 45000);
})();