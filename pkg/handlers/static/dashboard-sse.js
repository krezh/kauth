(function () {
  function localizeTimes(root) {
    (root || document).querySelectorAll("time[datetime]").forEach(function (el) {
      var date = new Date(el.getAttribute("datetime"));
      if (isNaN(date.getTime())) return;
      var pad = function (n) { return String(n).padStart(2, "0"); };
      el.textContent =
        date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) + " " +
        pad(date.getHours()) + ":" + pad(date.getMinutes()) + ":" + pad(date.getSeconds());
    });
  }

  var params = new URLSearchParams(location.search);
  var match = location.pathname.match(/^\/sessions\/([^/]+)/);
  if (match) params.set("session", decodeURIComponent(match[1]));

  var es = new EventSource("/sse/dashboard?" + params.toString());
  function swap(id) {
    return function (e) {
      var el = document.getElementById(id);
      if (el) {
        el.outerHTML = e.data;
        localizeTimes(document.getElementById(id));
      }
    };
  }
  ["stat-strip", "sessions-tbody", "detail-stats", "events-tbody", "nav-summary", "view-count"].forEach(function (id) {
    es.addEventListener(id, swap(id));
  });

  document.addEventListener("click", function (e) {
    var row = e.target.closest(".row-toggle");
    if (!row) return;
    var group = row.dataset.group;
    var open = row.classList.toggle("open");
    document.querySelectorAll('.discovery-row[data-group="' + group + '"]').forEach(function (discoveryRow) {
      discoveryRow.classList.toggle("show", open);
    });
  });

  localizeTimes(document);
})();
