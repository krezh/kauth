(function () {
  var params = new URLSearchParams(location.search);
  var match = location.pathname.match(/^\/sessions\/([^/]+)/);
  if (match) params.set("session", decodeURIComponent(match[1]));

  var es = new EventSource("/sse/dashboard?" + params.toString());
  function swap(id) {
    return function (e) {
      var el = document.getElementById(id);
      if (el) el.outerHTML = e.data;
    };
  }
  ["stat-strip", "sessions-tbody", "detail-stats", "events-tbody"].forEach(function (id) {
    es.addEventListener(id, swap(id));
  });
})();
