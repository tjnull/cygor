/*
 * Cygor Scan Timeline (D3.js v7)
 * Renders all scan start and completion times on a horizontal time axis.
 * Supports filters: All | First Completed | Most Recent Completed
 * Works with dashboard and popup modal.
 */

(function() {
  // --- internal config ---
  const MARGIN = { top: 25, right: 80, bottom: 70, left: 60 };
  const MIN_HEIGHT = 300;
  const MAX_HEIGHT = 500;
  const COLOR_STARTED = "#0d6efd";
  const COLOR_COMPLETED = "#ffc107";
  const DARK_BG = "#0a0a0a";
  const LIGHT_BG = "#ffffff";

  function parseTime(raw) {
    if (!raw) return null;
    try {
      if (typeof raw === "number") return new Date(raw);
      const d = new Date(raw);
      return isNaN(d.getTime()) ? null : d;
    } catch {
      return null;
    }
  }

  function extractHost(label) {
    if (!label) return "unknown";
    const ipv4 = String(label).match(/(\d{1,3}(?:\.\d{1,3}){3})/);
    if (ipv4) return ipv4[1];
    let base = label.split("/").pop();
    return base.replace(/\.(xml|nmap|gnmap|gz)$/gi, "") || label;
  }

  function getTheme() {
    const isLight = document.body.classList.contains("light-theme");
    return {
      text: isLight ? "#212529" : "#e0e0e0",
      grid: isLight ? "rgba(0,0,0,0.1)" : "rgba(255,255,255,0.06)",
      bg: isLight ? LIGHT_BG : DARK_BG
    };
  }

  function getFilter() {
    const el = document.getElementById("timelineFilter");
    if (!el) return "all";
    // Prioritize the current dropdown value over localStorage
    return el.value || "all";
  }

  function setFilter(v) {
    localStorage.setItem("cygor_timeline_filter", v);
    const el = document.getElementById("timelineFilter");
    if (el) el.value = v;
  }

  function getScanData() {
    let data = [];
    
    // Try to use the global _getScanTimesFromPage function if available (from index.html)
    // This function properly filters based on the source selection (CLI, ondemand, or all)
    if (typeof window._getScanTimesFromPage === 'function') {
      try {
        data = window._getScanTimesFromPage();
        if (Array.isArray(data) && data.length > 0) {
          return data;
        }
      } catch (e) {
        console.warn("Failed to get scan times from _getScanTimesFromPage:", e);
      }
    }
    
    // Fallback: try to get base scan times from canvas dataset
    try {
      const canvas = document.getElementById("scanTimeline");
      if (canvas?.dataset?.scantimes) {
        data = JSON.parse(canvas.dataset.scantimes);
      }
    } catch (e) {
      console.warn("Failed to load scan times:", e);
    }
    
    // If we have base scans, check if we should include ondemand scans
    const scanSourceFilter = document.getElementById('scanSourceFilter')?.value || 'all';
    if (scanSourceFilter === 'ondemand' || scanSourceFilter === 'all') {
      // Try to get ondemand scans from window
      const onDemandScans = (typeof window.onDemandScans !== 'undefined' && Array.isArray(window.onDemandScans))
        ? window.onDemandScans
        : [];
      
      if (scanSourceFilter === 'ondemand') {
        // Only ondemand scans
        return onDemandScans;
      } else if (scanSourceFilter === 'all') {
        // Combine both
        return [...(Array.isArray(data) ? data : []), ...onDemandScans];
      }
    } else if (scanSourceFilter === 'cli') {
      // Only CLI scans
      return Array.isArray(data) ? data : [];
    }
    
    return Array.isArray(data) ? data : [];
  }

  function filterData(data, filter) {
    if (filter === "all" || !Array.isArray(data)) return data;

    const sorted = [...data].sort((a, b) => {
      const aEnd = parseTime(a.end);
      const bEnd = parseTime(b.end);
      return aEnd - bEnd;
    });

    const count = sorted.length;
    if (count === 0) return data;

    // First 25% of scans
    if (filter === "first") {
      const firstCount = Math.max(1, Math.ceil(count * 0.25));
      return sorted.slice(0, firstCount);
    }

    // Last 25% of scans
    if (filter === "latest") {
      const lastCount = Math.max(1, Math.ceil(count * 0.25));
      return sorted.slice(-lastCount);
    }

    // Middle 50% of scans
    if (filter === "middle") {
      const quarterCount = Math.floor(count * 0.25);
      return sorted.slice(quarterCount, count - quarterCount);
    }

    return data;
  }

  function renderScanTimelineD3() {
    const container = document.getElementById("scanTimelineWrap");
    if (!container) {
      console.error("Container #scanTimelineWrap not found");
      return;
    }

    const scanTimes = filterData(getScanData(), getFilter());
    
    // Clear any existing content
    const oldSvg = container.querySelector("svg");
    const oldMessage = container.querySelector("div");
    if (oldSvg) oldSvg.remove();
    if (oldMessage) oldMessage.remove();

    if (!scanTimes.length) {
      container.innerHTML = "<div style='color: #a1a1aa; text-align: center; padding: 3rem 1rem; font-size: 1rem; line-height: 1.6;'>No scan timeline data available.</div>";
      return;
    }

    const parsed = scanTimes.map((s, i) => ({
      label: extractHost(s.label || s.path || `scan-${i+1}`),
      start: parseTime(s.start),
      end: parseTime(s.end)
    })).filter(d => d.start && d.end);

    if (!parsed.length) {
      container.innerHTML = "<div style='color: #a1a1aa; text-align: center; padding: 3rem 1rem; font-size: 1rem; line-height: 1.6;'>No valid scan data found.</div>";
      return;
    }

    parsed.sort((a,b) => a.end - b.end);

    const theme = getTheme();
    const containerWidth = container.clientWidth || 800;
    const width = Math.max(containerWidth - MARGIN.left - MARGIN.right, 600);

    // Calculate height with better scaling for few or many scans
    let height = MIN_HEIGHT;
    if (parsed.length > 10) {
      height = Math.min(MAX_HEIGHT, MIN_HEIGHT + (parsed.length - 10) * 8);
    } else if (parsed.length <= 5) {
      height = 280; // Even smaller datasets get reasonable height
    }


    // Performance optimization: For very large datasets, reduce visual complexity
    const isLargeDataset = parsed.length > 1000;
    const isHugeDataset = parsed.length > 10000;

    const svg = d3.select(container)
      .append("svg")
      .attr("width", width + MARGIN.left + MARGIN.right)
      .attr("height", height + MARGIN.top + MARGIN.bottom)
      .style("background", theme.bg)
      .style("border-radius", "4px")
      .style("display", "block");

    const g = svg.append("g").attr("transform", `translate(${MARGIN.left},${MARGIN.top})`);

    // Calculate time domain from earliest start to latest completion
    const allTimes = parsed.flatMap(d => [d.start, d.end]).filter(Boolean);
    const timeDomain = d3.extent(allTimes);

    const x = d3.scaleTime()
      .domain(timeDomain)
      .range([0, width])
      .nice();

    const y = d3.scaleLinear()
      .domain([0, parsed.length])
      .range([height, 0]);

    const xAxis = d3.axisBottom(x)
      .ticks(8)
      .tickSizeOuter(0)
      .tickFormat(d => ""); // We'll add custom labels below

    const yAxis = d3.axisLeft(y)
      .ticks(5)
      .tickFormat(d => Math.round(d))
      .tickSizeOuter(0);

    // Add X-axis
    const xAxisGroup = g.append("g")
      .attr("class", "x-axis")
      .attr("transform", `translate(0,${height})`)
      .call(xAxis);

    // Custom two-line date labels
    xAxisGroup.selectAll(".tick")
      .each(function(d) {
        const tick = d3.select(this);
        tick.select("text").remove(); // Remove default text

        // Add date (top line)
        tick.append("text")
          .attr("fill", theme.text)
          .attr("y", 9)
          .attr("dy", "0.71em")
          .attr("text-anchor", "middle")
          .style("font-size", "12px")
          .style("font-weight", "600")
          .text(d3.timeFormat("%m/%d/%Y")(d));

        // Add time (bottom line)
        tick.append("text")
          .attr("fill", theme.text)
          .attr("y", 28)
          .attr("dy", "0.71em")
          .attr("text-anchor", "middle")
          .style("font-size", "12px")
          .style("font-weight", "500")
          .text(d3.timeFormat("%I:%M %p")(d));
      });

    // Add Y-axis
    g.append("g")
      .attr("class", "y-axis")
      .call(yAxis)
      .selectAll("text")
      .attr("fill", theme.text)
      .style("font-size", "13px")
      .style("font-weight", "500");

    // Add Y-axis label
    g.append("text")
      .attr("transform", "rotate(-90)")
      .attr("x", -height / 2)
      .attr("y", -45)
      .attr("text-anchor", "middle")
      .attr("fill", theme.text)
      .style("font-size", "14px")
      .style("font-weight", "600")
      .text("Completed Scans");

    g.selectAll(".domain, .tick line")
      .attr("stroke", theme.grid);

    // Grid lines for better readability
    g.append("g")
      .attr("class", "grid")
      .attr("opacity", 0.1)
      .call(d3.axisLeft(y)
        .ticks(5)
        .tickSize(-width)
        .tickFormat("")
      )
      .selectAll("line")
      .attr("stroke", theme.grid);

    // Remove any existing tooltips before creating a new one
    d3.selectAll(".d3-tooltip").remove();

    // Create tooltip FIRST before adding any markers
    const tooltip = d3.select("body")
      .append("div")
      .attr("class", "d3-tooltip")
      .style("position", "absolute")
      .style("background", "rgba(0,0,0,0.95)")
      .style("color", "#fff")
      .style("padding", "10px 14px")
      .style("border-radius", "6px")
      .style("font-size", "13px")
      .style("font-weight", "500")
      .style("line-height", "1.6")
      .style("pointer-events", "none")
      .style("opacity", 0)
      .style("z-index", "10000")
      .style("box-shadow", "0 4px 12px rgba(0,0,0,0.4)");

    // Line connecting scans (cumulative)
    // Start from the earliest scan start time (beginning of timeline)
    const earliestStart = d3.min(parsed, d => d.start);
    const cumulative = [
      { x: earliestStart, y: 0 }, // Start at zero scans at the beginning
      ...parsed.map((d,i) => ({ x: d.end, y: i+1 }))
    ];

    const line = d3.line()
      .x(d => x(d.x))
      .y(d => y(d.y))
      .curve(d3.curveStepAfter);

    g.append("path")
      .datum(cumulative)
      .attr("class", "cumulative-line")
      .attr("data-group", "started")
      .attr("fill", "none")
      .attr("stroke", COLOR_STARTED)
      .attr("stroke-width", 2.5)
      .attr("opacity", 0.8)
      .attr("d", line);

    // Blue start markers removed per user request - keeping only yellow completion markers

    // Completion markers (yellow circles) - optimize size for large datasets
    const completeMarkerSize = isHugeDataset ? 3 : (isLargeDataset ? 4 : 6);
    const completeMarkerHoverSize = isHugeDataset ? 4 : (isLargeDataset ? 6 : 8);

    g.selectAll("circle.complete-marker")
      .data(parsed)
      .enter()
      .append("circle")
      .attr("class", "complete-marker")
      .attr("data-group", "completed")
      .attr("cx", d => x(d.end))
      .attr("cy", (d,i) => y(i+1))
      .attr("r", completeMarkerSize)
      .attr("fill", COLOR_COMPLETED)
      .attr("stroke", "#fff")
      .attr("stroke-width", isHugeDataset ? 1 : 2)
      .style("cursor", "pointer")
      .on("mouseover", (evt, d) => {
        if (!isHugeDataset) {
          d3.select(evt.target)
            .transition()
            .duration(100)
            .attr("r", completeMarkerHoverSize);
        }
        tooltip.transition().duration(100).style("opacity", 0.95);
        tooltip.html(`<div style="font-weight: 600; margin-bottom: 4px;">${d.label}</div><div style="font-size: 12px; opacity: 0.9;">Started: ${d.start.toLocaleString()}</div><div style="font-size: 12px; opacity: 0.9;">Completed: ${d.end.toLocaleString()}</div>`)
          .style("left", (evt.pageX + 12) + "px")
          .style("top", (evt.pageY - 24) + "px");
      })
      .on("mouseout", (evt) => {
        if (!isHugeDataset) {
          d3.select(evt.target)
            .transition()
            .duration(100)
            .attr("r", completeMarkerSize);
        }
        tooltip.transition().duration(200).style("opacity", 0);
      })
      .on("click", (evt, d) => {
        const ipMatch = String(d.label).match(/(\d{1,3}(?:\.\d{1,3}){3})/);
        const ip = ipMatch ? ipMatch[1] : d.label;
        const targetUrl = `/hosts?ip=${encodeURIComponent(ip)}`;
        window.open(targetUrl, "_blank", "noopener,noreferrer");
      });

    // X-axis label - positioned below the time labels with adequate spacing
    g.append("text")
      .attr("x", width / 2)
      .attr("y", height + 58)
      .attr("text-anchor", "middle")
      .attr("fill", theme.text)
      .style("font-size", "13px")
      .style("font-weight", "600")
      .text("Scan Completion Time");

    // Setup legend click handlers
    attachLegendHandlers();
  }

  function attachLegendHandlers() {
    const legend = document.getElementById("scanTimelineLegend");
    if (!legend) return;

    // Store visibility state
    const visibility = { started: true, completed: true };

    // Remove old handlers by cloning
    legend.querySelectorAll('.legend-item').forEach(el => {
      const newEl = el.cloneNode(true);
      el.parentNode.replaceChild(newEl, el);
    });

    // Attach new handlers
    legend.querySelectorAll('.legend-item').forEach(el => {
      el.addEventListener('click', () => {
        const group = el.getAttribute('data-group');
        if (!group) return;

        // Toggle visibility state
        visibility[group] = !visibility[group];

        // Update visual state of legend item
        if (visibility[group]) {
          el.classList.remove('dim');
        } else {
          el.classList.add('dim');
        }

        // Toggle SVG elements
        const svg = document.querySelector('#scanTimelineWrap svg');
        if (svg) {
          d3.select(svg)
            .selectAll(`[data-group="${group}"]`)
            .transition()
            .duration(200)
            .style("opacity", visibility[group] ? (group === "started" ? 0.8 : 1) : 0);
        }
      });
    });
  }

  // ---- Global attach ----
  window.renderScanTimelineD3 = renderScanTimelineD3;

  // Initial auto-render
  document.addEventListener("DOMContentLoaded", () => {
    try {
      renderScanTimelineD3();
    } catch (e) {
      console.error("[ScanTimelineD3] render error:", e);
    }
  });

  // Sync with filter dropdown if present
  document.addEventListener("change", (evt) => {
    if (evt.target.id === "timelineFilter") {
      setFilter(evt.target.value);
      try { renderScanTimelineD3(); } catch (e) { console.error(e); }
    }
  });

})();
