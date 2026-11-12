// Dependency-free SVG timeline chart for the dashboard (works offline).
(function () {
  "use strict";

  const container = document.getElementById("timeline-chart");
  const dataNode = document.getElementById("timeline-data");
  if (!container || !dataNode) return;

  const data = JSON.parse(dataNode.textContent);
  if (!data.length) return;

  const NS = "http://www.w3.org/2000/svg";
  const pad = { top: 12, right: 12, bottom: 26, left: 44 };

  function el(name, attrs) {
    const node = document.createElementNS(NS, name);
    for (const key in attrs) node.setAttribute(key, attrs[key]);
    return node;
  }

  function niceMax(value) {
    if (value <= 5) return 5;
    const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
    for (const step of [1, 2, 2.5, 5, 10]) {
      if (step * magnitude >= value) return step * magnitude;
    }
    return value;
  }

  // Bucket times arrive as naive UTC ISO strings; show them in the display
  // timezone (Europe/Istanbul by default) using the browser's Intl support.
  const timeZone = container.dataset.timezone || "UTC";
  const toDate = iso => new Date(iso + "Z");
  const fmt = options => new Intl.DateTimeFormat("en-GB", Object.assign({ timeZone, hourCycle: "h23" }, options));
  const fmtTime = fmt({ hour: "2-digit", minute: "2-digit" });
  const fmtDay = fmt({ day: "numeric", month: "short" });
  const fmtDayTime = fmt({ day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const fmtFull = fmt({ year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });

  function label(iso, spanMs) {
    const d = toDate(iso);
    if (spanMs > 14 * 86400000) return fmtDay.format(d);
    if (spanMs > 2 * 86400000) return fmtDayTime.format(d);
    return fmtTime.format(d);
  }

  function draw() {
    container.innerHTML = "";
    const width = container.clientWidth;
    const height = container.clientHeight;
    const w = width - pad.left - pad.right;
    const h = height - pad.top - pad.bottom;
    const max = niceMax(Math.max(...data.map(d => d.total)));
    const n = data.length;
    const x = i => pad.left + (n === 1 ? w / 2 : (i / (n - 1)) * w);
    const y = v => pad.top + h - (v / max) * h;
    const spanMs = toDate(data[n - 1].time) - toDate(data[0].time);

    const svg = el("svg", { viewBox: `0 0 ${width} ${height}` });
    const defs = el("defs", {});
    const grad = el("linearGradient", { id: "area-grad", x1: 0, y1: 0, x2: 0, y2: 1 });
    grad.append(el("stop", { offset: "0%", "stop-color": "#38bdf8", "stop-opacity": 0.35 }));
    grad.append(el("stop", { offset: "100%", "stop-color": "#38bdf8", "stop-opacity": 0 }));
    defs.append(grad);
    svg.append(defs);

    for (let t = 0; t <= 4; t++) {
      const value = (max / 4) * t;
      svg.append(el("line", { class: "grid-line", x1: pad.left, x2: pad.left + w, y1: y(value), y2: y(value) }));
      const text = el("text", { class: "axis-text", x: pad.left - 8, y: y(value) + 4, "text-anchor": "end" });
      text.textContent = Math.round(value).toLocaleString();
      svg.append(text);
    }

    const ticks = Math.min(n, Math.max(2, Math.floor(w / 90)));
    for (let t = 0; t < ticks; t++) {
      const i = Math.round((t / Math.max(1, ticks - 1)) * (n - 1));
      const text = el("text", { class: "axis-text", x: x(i), y: height - 6, "text-anchor": t === 0 ? "start" : t === ticks - 1 ? "end" : "middle" });
      text.textContent = label(data[i].time, spanMs);
      svg.append(text);
    }

    const line = key => data.map((d, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(d[key]).toFixed(1)}`).join("");
    const area = `${line("total")}L${x(n - 1)},${y(0)}L${x(0)},${y(0)}Z`;
    svg.append(el("path", { d: area, fill: "url(#area-grad)" }));
    svg.append(el("path", { d: line("total"), fill: "none", stroke: "#38bdf8", "stroke-width": 2, "stroke-linejoin": "round" }));
    svg.append(el("path", { d: line("errors"), fill: "none", stroke: "#f43f5e", "stroke-width": 2, "stroke-linejoin": "round" }));

    const hover = el("line", { class: "hover-line", y1: pad.top, y2: pad.top + h, visibility: "hidden" });
    const dot = el("circle", { r: 4, fill: "#38bdf8", stroke: "#0a1020", "stroke-width": 2, visibility: "hidden" });
    svg.append(hover, dot);
    container.append(svg);

    const tip = document.createElement("div");
    tip.className = "chart-tooltip";
    container.append(tip);

    const indexAt = event => {
      const rect = svg.getBoundingClientRect();
      const px = ((event.clientX - rect.left) / rect.width) * width;
      return Math.max(0, Math.min(n - 1, Math.round(((px - pad.left) / w) * (n - 1))));
    };

    // Clicking a point opens the Log Explorer limited to that time interval.
    const explorerUrl = container.dataset.explorer;
    const bucketMs = n > 1 ? toDate(data[1].time) - toDate(data[0].time) : 60000;
    if (explorerUrl) {
      svg.addEventListener("click", event => {
        const start = toDate(data[indexAt(event)].time);
        const end = new Date(start.getTime() + bucketMs - 1000);
        window.location.href = `${explorerUrl}&start=${encodeURIComponent(start.toISOString())}&end=${encodeURIComponent(end.toISOString())}`;
      });
    }

    svg.addEventListener("mousemove", event => {
      const i = indexAt(event);
      const d = data[i];
      hover.setAttribute("x1", x(i)); hover.setAttribute("x2", x(i)); hover.setAttribute("visibility", "visible");
      dot.setAttribute("cx", x(i)); dot.setAttribute("cy", y(d.total)); dot.setAttribute("visibility", "visible");
      tip.style.display = "block";
      tip.style.left = (x(i) / width) * 100 + "%";
      tip.style.top = y(d.total) + "px";
      tip.innerHTML = "";
      const title = document.createElement("div");
      title.className = "muted";
      title.textContent = fmtFull.format(toDate(d.time));
      const body = document.createElement("div");
      body.textContent = `${d.total.toLocaleString()} records · ${d.errors.toLocaleString()} errors`;
      tip.append(title, body);
      if (explorerUrl) {
        const hint = document.createElement("div");
        hint.className = "muted";
        hint.textContent = "Click to view these records";
        tip.append(hint);
      }
    });
    svg.addEventListener("mouseleave", () => {
      hover.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); tip.style.display = "none";
    });
  }

  draw();
  let timer;
  window.addEventListener("resize", () => { clearTimeout(timer); timer = setTimeout(draw, 150); });
})();
