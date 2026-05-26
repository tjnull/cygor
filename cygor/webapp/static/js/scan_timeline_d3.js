/*
 * Cygor Scan Timeline - Enhanced Gantt Chart (D3.js v7)
 * Features: scrollable lanes, search, date picker, export, mini-map, grouping, animations, light theme
 */

(function() {
  // === Configuration ===
  const config = {
    rowHeight: 50,              // Increased even more for clarity
    minBarWidth: 12,            // Larger minimum bar width
    barOpacity: 0.9,
    barHoverOpacity: 1,
    animationDuration: 300,
    maxVisibleLanes: 15,        // Max lanes before scrolling kicks in
    scrollbarWidth: 12,
    colors: {
      // Cygor color scheme
      dark: {
        background: '#000000',
        cardBg: '#0a0a0a',
        gridLine: '#1a1a1a',
        text: '#e4e4e7',
        textMuted: '#71717a',
        accent: '#0d6efd',
        cliScan: '#3b82f6',       // Bright blue
        ondemandScan: '#8b5cf6',  // Purple
        completed: '#22c55e',     // Green
        running: '#eab308',       // Yellow
        hover: '#1e293b'
      },
      light: {
        background: '#f5f7fa',
        cardBg: '#ffffff',
        gridLine: '#e5e7eb',
        text: '#212529',
        textMuted: '#6c757d',
        accent: '#0d6efd',
        cliScan: '#3b82f6',
        ondemandScan: '#8b5cf6',
        completed: '#22c55e',
        running: '#eab308',
        hover: '#f1f5f9'
      }
    }
  };

  // === Utility Functions ===

  function getTheme() {
    return document.body.classList.contains('light-theme') ? 'light' : 'dark';
  }

  function getColors() {
    return config.colors[getTheme()];
  }

  function parseTime(raw) {
    if (!raw) return null;
    try {
      if (typeof raw === "number") return new Date(raw);
      const d = new Date(raw);
      return isNaN(d.getTime()) ? null : d;
    } catch (e) {
      console.warn('[Timeline] Failed to parse time:', raw, e);
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

  function extractSubnet(ip) {
    const match = String(ip).match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/);
    return match ? match[1] + '.0/24' : 'Unknown';
  }

  function formatDuration(ms) {
    if (!ms || ms < 0) return "< 1s";
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  }

  function formatDateTime(date) {
    if (!date) return "N/A";
    return date.toLocaleString('en-US', {
      month: '2-digit',
      day: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    });
  }

  function formatDateShort(date) {
    if (!date) return "N/A";
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  // Smart time formatting based on time range
  function formatTimeAxis(date, timeRange) {
    const daysDiff = timeRange / (1000 * 60 * 60 * 24);

    if (daysDiff < 1) {
      // Less than 1 day: show HH:MM
      return d3.timeFormat("%H:%M")(date);
    } else if (daysDiff <= 7) {
      // 1-7 days: show MM/DD HH:MM
      return d3.timeFormat("%m/%d %H:%M")(date);
    } else {
      // More than 7 days: show MM/DD
      return d3.timeFormat("%m/%d")(date);
    }
  }

  function getFilter() {
    const el = document.getElementById("timelineFilter");
    if (!el) return "all";
    return el.value || "all";
  }

  function getScanData() {
    let data = [];

    if (typeof window._getScanTimesFromPage === 'function') {
      try {
        data = window._getScanTimesFromPage();
        if (Array.isArray(data) && data.length > 0) {
          console.log('[Timeline] Loaded scan data from _getScanTimesFromPage:', data.length, 'scans');
          return data;
        }
      } catch (e) {
        console.warn("[Timeline] Failed to get scan times from _getScanTimesFromPage:", e);
      }
    }

    try {
      const canvas = document.getElementById("scanTimeline");
      if (canvas?.dataset?.scantimes) {
        data = JSON.parse(canvas.dataset.scantimes);
        console.log('[Timeline] Loaded scan data from DOM:', data.length, 'scans');
      }
    } catch (e) {
      console.warn("[Timeline] Failed to load scan times:", e);
    }

    const scanSourceFilter = document.getElementById('scanSourceFilter')?.value || 'all';
    if (scanSourceFilter === 'ondemand' || scanSourceFilter === 'all') {
      const onDemandScans = (typeof window.onDemandScans !== 'undefined' && Array.isArray(window.onDemandScans))
        ? window.onDemandScans
        : [];

      if (scanSourceFilter === 'ondemand') {
        console.log('[Timeline] Filter: on-demand only -', onDemandScans.length, 'scans');
        return onDemandScans;
      } else if (scanSourceFilter === 'all') {
        const combined = [...(Array.isArray(data) ? data : []), ...onDemandScans];
        console.log('[Timeline] Filter: all scans -', combined.length, 'total (', data.length, 'CLI +', onDemandScans.length, 'on-demand)');
        return combined;
      }
    } else if (scanSourceFilter === 'cli') {
      console.log('[Timeline] Filter: CLI only -', data.length, 'scans');
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

    if (filter === "first") {
      const firstCount = Math.max(1, Math.ceil(count * 0.25));
      console.log('[Timeline] Filter: first 25% -', firstCount, 'of', count, 'scans');
      return sorted.slice(0, firstCount);
    }

    if (filter === "latest") {
      const lastCount = Math.max(1, Math.ceil(count * 0.25));
      console.log('[Timeline] Filter: latest 25% -', lastCount, 'of', count, 'scans');
      return sorted.slice(-lastCount);
    }

    if (filter === "middle") {
      const quarterCount = Math.floor(count * 0.25);
      console.log('[Timeline] Filter: middle 50% -', (count - 2 * quarterCount), 'of', count, 'scans');
      return sorted.slice(quarterCount, count - quarterCount);
    }

    return data;
  }

  // Deduplicate scans by host
  function deduplicateHosts(scans) {
    const uniqueHosts = new Map();
    scans.forEach(scan => {
      const key = `${scan.label}_${scan.start?.getTime()}`;
      if (!uniqueHosts.has(key)) {
        uniqueHosts.set(key, scan);
      }
    });
    const deduplicated = Array.from(uniqueHosts.values());
    if (deduplicated.length !== scans.length) {
      console.log('[Timeline] Deduplicated', scans.length - deduplicated.length, 'duplicate scans');
    }
    return deduplicated;
  }

  // === Export Functions ===

  function exportAsSVG(svgElement, filename = 'cygor-scan-timeline.svg') {
    try {
      const svgData = new XMLSerializer().serializeToString(svgElement);
      const blob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      console.log('[Timeline] Exported as SVG:', filename);
    } catch (e) {
      console.error('[Timeline] Export SVG failed:', e);
      showAlert('Failed to export SVG. Check console for details.', 'danger');
    }
  }

  function exportAsPNG(svgElement, filename = 'cygor-scan-timeline.png') {
    try {
      const svgData = new XMLSerializer().serializeToString(svgElement);
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      const img = new Image();

      const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(svgBlob);

      img.onload = function() {
        canvas.width = img.width * 2;  // 2x for retina
        canvas.height = img.height * 2;
        ctx.scale(2, 2);
        ctx.fillStyle = getColors().background;
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0);

        canvas.toBlob(function(blob) {
          const pngUrl = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = pngUrl;
          link.download = filename;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          URL.revokeObjectURL(pngUrl);
          URL.revokeObjectURL(url);
          console.log('[Timeline] Exported as PNG:', filename);
        });
      };

      img.onerror = function() {
        console.error('[Timeline] Export PNG failed: image load error');
        showAlert('Failed to export PNG. Try SVG export instead.', 'danger');
        URL.revokeObjectURL(url);
      };

      img.src = url;
    } catch (e) {
      console.error('[Timeline] Export PNG failed:', e);
      showAlert('Failed to export PNG. Check console for details.', 'danger');
    }
  }

  // === Main Render Function ===

  // Prevent concurrent renders
  let isRendering = false;
  let pendingRender = false;

  function renderScanTimelineD3() {
    // If already rendering, mark for re-render after completion
    if (isRendering) {
      pendingRender = true;
      console.log('[Timeline] Render in progress, queuing next render');
      return;
    }

    isRendering = true;

    const container = document.getElementById("scanTimelineWrap");
    if (!container) {
      console.error("[Timeline] Container #scanTimelineWrap not found");
      isRendering = false;
      return;
    }

    const colors = getColors();
    const scanTimes = filterData(getScanData(), getFilter());
    console.log(`[Timeline] Rendering with ${scanTimes.length} scans`);

    // Clear existing content
    container.innerHTML = '';

    if (!scanTimes.length) {
      container.innerHTML = `
        <div style='color: ${colors.textMuted}; text-align: center; padding: 4rem 1rem; font-size: 1rem; line-height: 1.6;'>
          <i class='bi bi-clock-history' style='font-size: 4rem; opacity: 0.2; display: block; margin-bottom: 1.5rem;'></i>
          <div style='font-size: 1.1rem; font-weight: 500;'>No scan timeline data available</div>
          <div style='font-size: 0.9rem; margin-top: 0.5rem;'>Run some scans to see the timeline</div>
        </div>`;
      return;
    }

    // Parse and prepare data
    let parsed = scanTimes.map((s, i) => {
      const start = parseTime(s.start);
      const end = parseTime(s.end);

      if (!start) {
        console.warn('[Timeline] Scan missing start time:', s);
        return null;
      }

      const scanType = s.source || (s.label && s.label.includes('ondemand') ? 'ondemand' : 'cli');
      const host = extractHost(s.label || s.path || `scan-${i+1}`);

      return {
        label: host,
        subnet: extractSubnet(host),
        start: start,
        end: end || start,
        hasEnd: !!end,
        duration: (end && start) ? (end - start) : 0,
        scanType: scanType,
        fullLabel: s.label || s.path || `scan-${i+1}`,
        index: i
      };
    }).filter(d => d !== null);

    if (!parsed.length) {
      container.innerHTML = `
        <div style='color: ${colors.textMuted}; text-align: center; padding: 3rem 1rem;'>
          No valid scan data found (missing timestamps).
        </div>`;
      console.warn('[Timeline] No valid scans after parsing (all missing start times)');
      return;
    }

    // Deduplicate
    parsed = deduplicateHosts(parsed);

    // Sort by start time
    parsed.sort((a, b) => a.start - b.start);

    // Check grouping mode - preserve context
    const groupBy = window.timelineGroupBy || 'host'; // 'host' or 'subnet'
    console.log('[Timeline] Grouping by:', groupBy);

    // Group data
    const groups = new Map();
    parsed.forEach(scan => {
      const key = groupBy === 'subnet' ? scan.subnet : scan.label;
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key).push(scan);
    });

    const lanes = Array.from(groups.keys());
    console.log('[Timeline] Total lanes:', lanes.length);

    // === Dimensions ===

    const isModal = container.closest('#chartPopupModal') !== null;
    const margin = { top: 100, right: 40, bottom: 80, left: 200 }; // Increased left margin
    const containerWidth = container.getBoundingClientRect().width;
    const width = Math.max(1000, isModal ? containerWidth * 0.95 : containerWidth) - margin.left - margin.right;

    // Calculate scrollable height
    const needsScroll = lanes.length > config.maxVisibleLanes;
    const visibleHeight = Math.min(lanes.length, config.maxVisibleLanes) * config.rowHeight;
    const totalHeight = lanes.length * config.rowHeight;
    const height = needsScroll ? visibleHeight : totalHeight;

    console.log('[Timeline] Dimensions:', {
      lanes: lanes.length,
      needsScroll,
      visibleHeight,
      totalHeight,
      displayHeight: height
    });

    // === Scales ===

    const timeExtent = d3.extent(parsed.flatMap(d => [d.start, d.end]));

    // Check for date range filter - preserve context
    let dateRangeStart = window.timelineDateRange?.start;
    let dateRangeEnd = window.timelineDateRange?.end;

    if (dateRangeStart && dateRangeEnd) {
      timeExtent[0] = new Date(dateRangeStart);
      timeExtent[1] = new Date(dateRangeEnd);
      console.log('[Timeline] Date range filter applied:', timeExtent);
    }

    const timeRange = timeExtent[1] - timeExtent[0];

    const xScale = d3.scaleTime()
      .domain(timeExtent)
      .range([0, width])
      .nice();

    const yScale = d3.scaleBand()
      .domain(lanes)
      .range([0, totalHeight])
      .padding(0.3); // More padding for clarity

    // === Create SVG with Scrollable Container ===

    const svgContainer = d3.create("div")
      .attr("class", "timeline-svg-container")
      .style("position", "relative")
      .style("width", "100%")
      .style("height", (height + margin.top + margin.bottom + 80) + "px")
      .style("background", colors.cardBg)
      .style("border-radius", "0 0 6px 6px");

    // Create a wrapper for the scrollable content area with proper clipping
    const contentWrapper = svgContainer.append("div")
      .attr("class", "timeline-content-wrapper")
      .style("position", "absolute")
      .style("top", margin.top + "px")
      .style("left", margin.left + "px")
      .style("width", (width + margin.right) + "px")
      .style("height", height + "px")
      .style("overflow", "hidden");

    const scrollWrapper = contentWrapper.append("div")
      .attr("class", "timeline-scroll-wrapper")
      .style("position", "relative")
      .style("width", "100%")
      .style("height", "100%")
      .style("overflow-y", needsScroll ? "auto" : "hidden")
      .style("overflow-x", "hidden");

    // Custom scrollbar styling
    if (needsScroll) {
      const scrollbarStyle = document.createElement('style');
      scrollbarStyle.textContent = `
        .timeline-scroll-wrapper::-webkit-scrollbar {
          width: ${config.scrollbarWidth}px;
        }
        .timeline-scroll-wrapper::-webkit-scrollbar-track {
          background: ${colors.background};
          border-radius: 6px;
        }
        .timeline-scroll-wrapper::-webkit-scrollbar-thumb {
          background: ${colors.accent};
          border-radius: 6px;
          border: 2px solid ${colors.background};
        }
        .timeline-scroll-wrapper::-webkit-scrollbar-thumb:hover {
          background: ${colors.completed};
        }
      `;
      document.head.appendChild(scrollbarStyle);
    }

    const svg = scrollWrapper.append("svg")
      .attr("width", width + margin.right)
      .attr("height", totalHeight)
      .attr("id", "timelineSvg");

    const g = svg.append("g")
      .attr("transform", `translate(0,0)`);

    // === Controls Bar ===

    const controlsDiv = d3.create("div")
      .attr("class", "timeline-controls")
      .style("padding", "1rem")
      .style("background", colors.cardBg)
      .style("border-bottom", `1px solid ${colors.gridLine}`)
      .style("border-radius", "6px 6px 0 0")
      .style("display", "flex")
      .style("gap", "0.75rem")
      .style("flex-wrap", "wrap")
      .style("align-items", "center");

    // Search input - preserve context
    const searchInput = d3.create("input")
      .attr("type", "text")
      .attr("id", "timelineSearch")
      .attr("placeholder", "🔍 Search by IP or hostname...")
      .attr("value", window.timelineSearchQuery || '')
      .style("flex", "1")
      .style("min-width", "220px")
      .style("padding", "0.6rem 0.9rem")
      .style("background", colors.background)
      .style("border", `1px solid ${colors.gridLine}`)
      .style("border-radius", "6px")
      .style("color", colors.text)
      .style("font-size", "13px");

    // Date range inputs with flexible text format
    const dateRangeDiv = d3.create("div")
      .style("display", "flex")
      .style("gap", "0.5rem")
      .style("align-items", "center");

    dateRangeDiv.append("span")
      .style("color", colors.textMuted)
      .style("font-size", "13px")
      .style("font-weight", "500")
      .text("📅 Date Range:");

    const startDateInput = d3.create("input")
      .attr("type", "text")
      .attr("id", "timelineStartDate")
      .attr("placeholder", "MM/DD/YYYY or YYYY-MM-DD")
      .style("padding", "0.5rem 0.7rem")
      .style("background", colors.background)
      .style("border", `1px solid ${colors.gridLine}`)
      .style("border-radius", "6px")
      .style("color", colors.text)
      .style("font-size", "12px")
      .style("width", "160px");

    const endDateInput = d3.create("input")
      .attr("type", "text")
      .attr("id", "timelineEndDate")
      .attr("placeholder", "MM/DD/YYYY or YYYY-MM-DD")
      .style("padding", "0.5rem 0.7rem")
      .style("background", colors.background)
      .style("border", `1px solid ${colors.gridLine}`)
      .style("border-radius", "6px")
      .style("color", colors.text)
      .style("font-size", "12px")
      .style("width", "160px");

    const applyDateBtn = d3.create("button")
      .attr("class", "btn-timeline")
      .style("padding", "0.5rem 0.8rem")
      .style("background", colors.accent)
      .style("border", `1px solid ${colors.accent}`)
      .style("border-radius", "6px")
      .style("color", "#fff")
      .style("font-size", "12px")
      .style("font-weight", "600")
      .style("cursor", "pointer")
      .style("transition", "all 0.2s")
      .html("Apply")
      .on("click", applyDateRange);

    const clearDateBtn = d3.create("button")
      .attr("class", "btn-timeline")
      .style("padding", "0.5rem 0.8rem")
      .style("background", colors.background)
      .style("border", `1px solid ${colors.gridLine}`)
      .style("border-radius", "6px")
      .style("color", colors.text)
      .style("font-size", "12px")
      .style("font-weight", "600")
      .style("cursor", "pointer")
      .style("transition", "all 0.2s")
      .html("Clear")
      .on("click", function() {
        startDateInput.node().value = '';
        endDateInput.node().value = '';
        window.timelineDateRange = null;
        console.log('[Timeline] Date range cleared');
        renderScanTimelineD3();
      });

    dateRangeDiv.node().appendChild(startDateInput.node());
    dateRangeDiv.node().appendChild(document.createTextNode(" — "));
    dateRangeDiv.node().appendChild(endDateInput.node());
    dateRangeDiv.node().appendChild(applyDateBtn.node());
    dateRangeDiv.node().appendChild(clearDateBtn.node());

    // Grouping toggle
    const groupToggle = d3.create("button")
      .attr("class", "btn-timeline")
      .style("padding", "0.6rem 0.9rem")
      .style("background", groupBy === 'subnet' ? colors.accent : colors.background)
      .style("border", `1px solid ${groupBy === 'subnet' ? colors.accent : colors.gridLine}`)
      .style("border-radius", "6px")
      .style("color", groupBy === 'subnet' ? '#fff' : colors.text)
      .style("font-size", "13px")
      .style("font-weight", "600")
      .style("cursor", "pointer")
      .style("transition", "all 0.2s")
      .html(`<i class="bi bi-diagram-3"></i> ${groupBy === 'subnet' ? 'By Subnet' : 'By Host'}`)
      .on("click", function() {
        window.timelineGroupBy = groupBy === 'host' ? 'subnet' : 'host';
        console.log('[Timeline] Toggling group mode to:', window.timelineGroupBy);
        renderScanTimelineD3();
      });

    // Export dropdown
    const exportBtn = d3.create("div")
      .attr("class", "dropdown")
      .html(`
        <button class="btn-timeline dropdown-toggle" type="button" data-bs-toggle="dropdown"
          style="padding: 0.6rem 0.9rem; background: ${colors.background}; border: 1px solid ${colors.gridLine};
          border-radius: 6px; color: ${colors.text}; font-size: 13px; font-weight: 600; cursor: pointer;">
          <i class="bi bi-download"></i> Export
        </button>
        <ul class="dropdown-menu" style="background: ${colors.cardBg}; border: 1px solid ${colors.gridLine};">
          <li><a class="dropdown-item export-svg" href="#" style="color: ${colors.text}; font-size: 13px; padding: 0.5rem 1rem;">
            <i class="bi bi-filetype-svg"></i> Export as SVG</a></li>
          <li><a class="dropdown-item export-png" href="#" style="color: ${colors.text}; font-size: 13px; padding: 0.5rem 1rem;">
            <i class="bi bi-filetype-png"></i> Export as PNG</a></li>
        </ul>
      `);

    // Stats display
    const statsDiv = d3.create("div")
      .style("margin-left", "auto")
      .style("padding", "0.6rem 0.9rem")
      .style("background", colors.hover)
      .style("border-radius", "6px")
      .style("font-size", "13px")
      .style("font-weight", "600")
      .style("color", colors.text)
      .html(`<i class="bi bi-graph-up"></i> ${lanes.length} ${groupBy === 'subnet' ? 'subnets' : 'hosts'} • ${parsed.length} scans`);

    controlsDiv.node().appendChild(searchInput.node());
    controlsDiv.node().appendChild(dateRangeDiv.node());
    controlsDiv.node().appendChild(groupToggle.node());
    controlsDiv.node().appendChild(exportBtn.node());
    controlsDiv.node().appendChild(statsDiv.node());

    // === Top X-Axis (Fixed) ===

    const tickCount = Math.min(10, Math.max(5, Math.floor(width / 100)));
    console.log('[Timeline] Using', tickCount, 'time axis ticks');

    const xAxisTop = d3.axisTop(xScale)
      .ticks(tickCount)
      .tickFormat(d => formatTimeAxis(d, timeRange));

    const topAxisSvg = svgContainer.insert("svg", ":first-child")
      .attr("class", "x-axis-top-fixed")
      .style("position", "absolute")
      .style("top", (margin.top - 35) + "px")
      .style("left", margin.left + "px")
      .style("width", width + "px")
      .style("height", "35px")
      .style("pointer-events", "none");

    topAxisSvg.append("g")
      .attr("transform", `translate(0,30)`)
      .call(xAxisTop)
      .call(g => {
        g.select(".domain").remove();
        g.selectAll(".tick line").remove();
        g.selectAll(".tick text")
          .attr("fill", colors.textMuted)
          .attr("font-size", "11px")
          .attr("font-weight", "600");
      });

    // === Grid Lines with Adaptive Ticks ===

    const xAxis = d3.axisBottom(xScale)
      .ticks(tickCount)
      .tickSize(-totalHeight)
      .tickFormat(d => formatTimeAxis(d, timeRange));

    g.append("g")
      .attr("class", "x-axis-grid")
      .attr("transform", `translate(0,${totalHeight})`)
      .call(xAxis)
      .call(g => {
        g.select(".domain").remove();
        g.selectAll(".tick line")
          .attr("stroke", colors.gridLine)
          .attr("stroke-dasharray", "3,6")
          .attr("stroke-opacity", 0.4);
        g.selectAll(".tick text")
          .attr("fill", colors.textMuted)
          .attr("font-size", "11px")
          .attr("font-weight", "500")
          .attr("dy", "1.5em");
      });

    // === Y Axis (Fixed on Left) ===

    const yAxis = d3.axisLeft(yScale)
      .tickSize(0);

    const yAxisSvg = svgContainer.append("svg")
      .attr("class", "y-axis-fixed")
      .style("position", "absolute")
      .style("top", margin.top + "px")
      .style("left", "0")
      .style("width", margin.left + "px")
      .style("height", height + "px")
      .style("background", colors.cardBg)
      .style("z-index", "10")
      .style("overflow", "hidden");

    const yAxisG = yAxisSvg.append("g")
      .attr("class", "y-axis-group")
      .attr("transform", `translate(${margin.left - 10},0)`);

    // Sync Y-axis scroll with content scroll
    scrollWrapper.on("scroll", function() {
      const scrollTop = this.scrollTop;
      yAxisG.attr("transform", `translate(${margin.left - 10},${-scrollTop})`);
    });

    yAxisG.call(yAxis)
      .call(g => {
        g.select(".domain").remove();
        g.selectAll(".tick text")
          .attr("fill", colors.accent)
          .attr("font-size", "13px")
          .attr("font-weight", "600")
          .attr("text-anchor", "end")
          .attr("x", -15)
          .style("cursor", "pointer")
          .style("pointer-events", "all")
          .on("click", function(event, d) {
            const ipMatch = String(d).match(/(\d{1,3}(?:\.\d{1,3}){3})/);
            const ip = ipMatch ? ipMatch[1] : d;
            if (groupBy === 'subnet') {
              searchInput.node().value = d.replace('/24', '');
              filterBySearch();
            } else {
              window.open(`/hosts?ip=${encodeURIComponent(ip)}`, "_blank", "noopener,noreferrer");
            }
          })
          .on("mouseenter", function() {
            d3.select(this)
              .attr("fill", colors.completed)
              .style("text-decoration", "underline");
          })
          .on("mouseleave", function() {
            d3.select(this)
              .attr("fill", colors.accent)
              .style("text-decoration", "none");
          });
      });

    // === Lane Backgrounds ===

    g.selectAll(".lane-bg")
      .data(lanes)
      .join("rect")
      .attr("class", "lane-bg")
      .attr("x", 0)
      .attr("y", d => yScale(d))
      .attr("width", width)
      .attr("height", yScale.bandwidth())
      .attr("fill", (d, i) => i % 2 === 0 ? 'transparent' : colors.hover)
      .attr("opacity", 0.2);

    // === Tooltip ===

    const tooltip = d3.select("body").append("div")
      .attr("class", "scan-timeline-tooltip")
      .style("position", "absolute")
      .style("visibility", "hidden")
      .style("background", colors.cardBg)
      .style("border", `2px solid ${colors.accent}`)
      .style("border-radius", "8px")
      .style("padding", "14px")
      .style("font-size", "13px")
      .style("color", colors.text)
      .style("pointer-events", "none")
      .style("z-index", "10000")
      .style("box-shadow", "0 8px 32px rgba(0,0,0,0.4)")
      .style("max-width", "380px");

    // === Draw Gantt Bars ===

    const filteredParsed = window.timelineSearchQuery
      ? parsed.filter(d => d.label.toLowerCase().includes(window.timelineSearchQuery.toLowerCase()))
      : parsed;

    console.log('[Timeline] Drawing', filteredParsed.length, 'bars (filtered from', parsed.length, ')');

    // Performance optimization: skip animations for large datasets
    const useAnimations = filteredParsed.length < 200;
    const animDuration = useAnimations ? config.animationDuration : 0;

    console.log('[Timeline] Animation:', useAnimations ? 'enabled' : 'disabled', 'for', filteredParsed.length, 'bars');

    // Main bars
    const bars = g.selectAll(".scan-bar-rect")
      .data(filteredParsed)
      .join("rect")
      .attr("class", "scan-bar-rect")
      .attr("x", d => xScale(d.start))
      .attr("y", d => {
        const lane = groupBy === 'subnet' ? d.subnet : d.label;
        return yScale(lane) + yScale.bandwidth() * 0.1;
      })
      .attr("width", d => {
        const w = xScale(d.end) - xScale(d.start);
        return Math.max(w, config.minBarWidth);
      })
      .attr("height", yScale.bandwidth() * 0.8)
      .attr("fill", d => d.scanType === 'ondemand' ? colors.ondemandScan : colors.cliScan)
      .attr("opacity", useAnimations ? 0 : config.barOpacity)
      .attr("rx", 8)
      .attr("ry", 8)
      .style("cursor", "pointer");

    // Apply animation only if enabled
    if (useAnimations) {
      bars.transition()
        .duration(animDuration)
        .attr("opacity", config.barOpacity)
        .end()
        .then(() => {
          attachBarInteractions();
        })
        .catch(e => console.warn('[Timeline] Animation error:', e));
    } else {
      // Attach interactions immediately for non-animated renders
      attachBarInteractions();
    }

    function attachBarInteractions() {
        // Add hover effects after animation
        g.selectAll(".scan-bar-rect")
          .on("mouseenter", function(event, d) {
            d3.select(this)
              .transition()
              .duration(150)
              .attr("opacity", config.barHoverOpacity)
              .attr("stroke", colors.accent)
              .attr("stroke-width", 3);

            const scanTypeLabel = d.scanType === 'ondemand' ? 'On-Demand' : 'CLI';
            const statusLabel = d.hasEnd ? 'Completed' : 'Running';
            const statusColor = d.hasEnd ? colors.completed : colors.running;

            tooltip
              .style("visibility", "visible")
              .html(`
                <div style="margin-bottom: 12px; padding-bottom: 12px; border-bottom: 2px solid ${colors.gridLine};">
                  <div style="font-size: 16px; font-weight: 700; color: ${colors.accent}; margin-bottom: 6px;">
                    ${d.label}
                  </div>
                  <div style="font-size: 11px; color: ${colors.textMuted};">
                    ${d.fullLabel}
                  </div>
                </div>
                <div style="display: grid; grid-template-columns: auto 1fr; gap: 10px 14px; font-size: 13px;">
                  <span style="color: ${colors.textMuted}; font-weight: 600;">Type:</span>
                  <span style="background: ${d.scanType === 'ondemand' ? colors.ondemandScan : colors.cliScan};
                    padding: 4px 12px; border-radius: 14px; font-size: 11px; font-weight: 700; color: #fff;
                    display: inline-block; text-align: center;">${scanTypeLabel}</span>

                  <span style="color: ${colors.textMuted}; font-weight: 600;">Status:</span>
                  <span style="color: ${statusColor}; font-weight: 700;">
                    <i class="bi bi-circle-fill" style="font-size: 8px;"></i> ${statusLabel}
                  </span>

                  <span style="color: ${colors.textMuted}; font-weight: 600;">Started:</span>
                  <span style="color: ${colors.text};">${formatDateShort(d.start)}</span>

                  ${d.hasEnd ? `
                  <span style="color: ${colors.textMuted}; font-weight: 600;">Completed:</span>
                  <span style="color: ${colors.text};">${formatDateShort(d.end)}</span>

                  <span style="color: ${colors.textMuted}; font-weight: 600;">Duration:</span>
                  <span style="color: ${colors.completed}; font-weight: 700;">${formatDuration(d.duration)}</span>
                  ` : ''}
                </div>
                <div style="margin-top: 12px; padding-top: 12px; border-top: 2px solid ${colors.gridLine};
                  font-size: 11px; color: ${colors.textMuted}; text-align: center; font-weight: 600;">
                  <i class="bi bi-box-arrow-up-right"></i> Click to view host details
                </div>
              `);
          })
          .on("mousemove", function(event) {
            const tooltipNode = tooltip.node();
            const tooltipWidth = tooltipNode.offsetWidth;
            const tooltipHeight = tooltipNode.offsetHeight;

            let left = event.pageX + 18;
            let top = event.pageY - 12;

            if (left + tooltipWidth > window.innerWidth - 20) {
              left = event.pageX - tooltipWidth - 18;
            }
            if (top + tooltipHeight > window.innerHeight - 20) {
              top = event.pageY - tooltipHeight + 12;
            }

            tooltip
              .style("top", top + "px")
              .style("left", left + "px");
          })
          .on("mouseleave", function() {
            d3.select(this)
              .transition()
              .duration(150)
              .attr("opacity", config.barOpacity)
              .attr("stroke", "none");
            tooltip.style("visibility", "hidden");
          })
          .on("click", function(event, d) {
            const ipMatch = String(d.label).match(/(\d{1,3}(?:\.\d{1,3}){3})/);
            const ip = ipMatch ? ipMatch[1] : d.label;
            console.log('[Timeline] Opening host details for:', ip);
            window.open(`/hosts?ip=${encodeURIComponent(ip)}`, "_blank", "noopener,noreferrer");
          });
    }

    // Start markers
    const startMarkers = g.selectAll(".start-marker")
      .data(filteredParsed)
      .join("circle")
      .attr("class", "start-marker")
      .attr("cx", d => xScale(d.start))
      .attr("cy", d => {
        const lane = groupBy === 'subnet' ? d.subnet : d.label;
        return yScale(lane) + yScale.bandwidth() / 2;
      })
      .attr("r", 6)
      .attr("fill", colors.cliScan)
      .attr("stroke", colors.cardBg)
      .attr("stroke-width", 2.5)
      .style("pointer-events", "none")
      .attr("opacity", useAnimations ? 0 : 1);

    if (useAnimations) {
      startMarkers.transition()
        .duration(animDuration)
        .attr("opacity", 1);
    }

    // End markers
    const endMarkers = g.selectAll(".end-marker")
      .data(filteredParsed.filter(d => d.hasEnd))
      .join("circle")
      .attr("class", "end-marker")
      .attr("cx", d => xScale(d.end))
      .attr("cy", d => {
        const lane = groupBy === 'subnet' ? d.subnet : d.label;
        return yScale(lane) + yScale.bandwidth() / 2;
      })
      .attr("r", 6)
      .attr("fill", colors.completed)
      .attr("stroke", colors.cardBg)
      .attr("stroke-width", 2.5)
      .style("pointer-events", "none")
      .attr("opacity", useAnimations ? 0 : 1);

    if (useAnimations) {
      endMarkers.transition()
        .duration(animDuration)
        .attr("opacity", 1);
    }

    // === Title ===

    const titleDiv = svgContainer.insert("div", ":first-child")
      .style("padding", "1.25rem 1.5rem")
      .style("background", colors.cardBg)
      .style("border-bottom", `2px solid ${colors.gridLine}`);

    titleDiv.append("div")
      .style("font-size", "18px")
      .style("font-weight", "700")
      .style("color", colors.text)
      .style("margin-bottom", "4px")
      .html(`<i class="bi bi-clock-history" style="color: ${colors.accent};"></i> Scan Timeline`);

    titleDiv.append("div")
      .style("font-size", "13px")
      .style("color", colors.textMuted)
      .style("font-weight", "500")
      .html(`Showing ${filteredParsed.length} of ${parsed.length} scans${needsScroll ? ' • Scroll to see all hosts' : ''}`);

    // === Mini-map Navigator ===

    const minimapHeight = 70;
    const minimapMargin = { top: 20, bottom: 20 };

    const miniXScale = d3.scaleTime()
      .domain(timeExtent)
      .range([0, width]);

    const minimap = svgContainer.append("svg")
      .attr("class", "minimap")
      .style("position", "absolute")
      .style("bottom", "10px")
      .style("left", margin.left + "px")
      .style("width", width + "px")
      .style("height", minimapHeight + "px");

    minimap.append("rect")
      .attr("width", width)
      .attr("height", minimapHeight)
      .attr("fill", colors.background)
      .attr("stroke", colors.gridLine)
      .attr("stroke-width", 2)
      .attr("rx", 6);

    minimap.selectAll(".mini-bar")
      .data(filteredParsed)
      .join("rect")
      .attr("class", "mini-bar")
      .attr("x", d => miniXScale(d.start))
      .attr("y", 5)
      .attr("width", d => Math.max(3, miniXScale(d.end) - miniXScale(d.start)))
      .attr("height", minimapHeight - 10)
      .attr("fill", d => d.scanType === 'ondemand' ? colors.ondemandScan : colors.cliScan)
      .attr("opacity", 0.5);

    const brush = d3.brushX()
      .extent([[0, 0], [width, minimapHeight]])
      .on("brush end", brushed);

    minimap.append("g")
      .attr("class", "brush")
      .call(brush);

    function brushed(event) {
      if (event.selection) {
        const [x0, x1] = event.selection;
        const newDomain = [miniXScale.invert(x0), miniXScale.invert(x1)];
        xScale.domain(newDomain);

        g.select(".x-axis-grid").call(xAxis);

        // Update top axis as well
        topAxisSvg.select("g").call(xAxisTop);

        g.selectAll(".scan-bar-rect")
          .attr("x", d => xScale(d.start))
          .attr("width", d => Math.max(config.minBarWidth, xScale(d.end) - xScale(d.start)));
        g.selectAll(".start-marker").attr("cx", d => xScale(d.start));
        g.selectAll(".end-marker").attr("cx", d => xScale(d.end));
      }
    }

    // === Zoom Behavior ===

    const zoom = d3.zoom()
      .scaleExtent([1, 30])
      .translateExtent([[0, 0], [width, totalHeight]])
      .extent([[0, 0], [width, height]])
      .on("zoom", zoomed);

    svg.call(zoom);

    function zoomed(event) {
      const newXScale = event.transform.rescaleX(xScale);

      // Update bottom grid axis
      g.select(".x-axis-grid").call(d3.axisBottom(newXScale)
        .ticks(tickCount)
        .tickSize(-totalHeight)
        .tickFormat(d => formatTimeAxis(d, timeRange)))
        .call(g => {
          g.select(".domain").remove();
          g.selectAll(".tick line")
            .attr("stroke", colors.gridLine)
            .attr("stroke-dasharray", "3,6")
            .attr("stroke-opacity", 0.4);
          g.selectAll(".tick text")
            .attr("fill", colors.textMuted)
            .attr("font-size", "11px")
            .attr("font-weight", "500")
            .attr("dy", "1.5em");
        });

      // Update top axis
      topAxisSvg.select("g").call(d3.axisTop(newXScale)
        .ticks(tickCount)
        .tickFormat(d => formatTimeAxis(d, timeRange)))
        .call(g => {
          g.select(".domain").remove();
          g.selectAll(".tick line").remove();
          g.selectAll(".tick text")
            .attr("fill", colors.textMuted)
            .attr("font-size", "11px")
            .attr("font-weight", "600");
        });

      g.selectAll(".scan-bar-rect")
        .attr("x", d => newXScale(d.start))
        .attr("width", d => Math.max(config.minBarWidth, newXScale(d.end) - newXScale(d.start)));

      g.selectAll(".start-marker").attr("cx", d => newXScale(d.start));
      g.selectAll(".end-marker").attr("cx", d => newXScale(d.end));
    }

    // === Reset Button ===

    const resetZoomBtn = svgContainer.append("button")
      .attr("class", "reset-zoom-btn")
      .style("position", "absolute")
      .style("top", "20px")
      .style("right", "20px")
      .style("background", colors.accent)
      .style("color", "#ffffff")
      .style("border", "none")
      .style("border-radius", "8px")
      .style("padding", "10px 18px")
      .style("font-size", "13px")
      .style("font-weight", "700")
      .style("cursor", "pointer")
      .style("display", "none")
      .style("z-index", "100")
      .style("box-shadow", "0 4px 12px rgba(13, 110, 253, 0.4)")
      .style("transition", "all 0.2s")
      .html('<i class="bi bi-arrow-counterclockwise"></i> Reset View')
      .on("click", function() {
        svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
        xScale.domain(timeExtent);
        g.select(".x-axis-grid").call(xAxis);
        topAxisSvg.select("g").call(xAxisTop);
        g.selectAll(".scan-bar-rect")
          .attr("x", d => xScale(d.start))
          .attr("width", d => Math.max(config.minBarWidth, xScale(d.end) - xScale(d.start)));
        g.selectAll(".start-marker").attr("cx", d => xScale(d.start));
        g.selectAll(".end-marker").attr("cx", d => xScale(d.end));
        minimap.select(".brush").call(brush.move, null);
        d3.select(this).style("display", "none");
        console.log('[Timeline] View reset');
      })
      .on("mouseenter", function() {
        d3.select(this)
          .style("transform", "translateY(-3px)")
          .style("box-shadow", "0 6px 16px rgba(13, 110, 253, 0.6)");
      })
      .on("mouseleave", function() {
        d3.select(this)
          .style("transform", "translateY(0)")
          .style("box-shadow", "0 4px 12px rgba(13, 110, 253, 0.4)");
      });

    svg.on("zoom", function(event) {
      if (event.transform && (event.transform.k > 1.1 || Math.abs(event.transform.x) > 10)) {
        resetZoomBtn.style("display", "block");
      } else {
        resetZoomBtn.style("display", "none");
      }
    });

    // === Assemble DOM ===

    const wrapper = d3.create("div")
      .style("position", "relative")
      .style("width", "100%");

    wrapper.node().appendChild(controlsDiv.node());
    wrapper.node().appendChild(svgContainer.node());
    container.appendChild(wrapper.node());

    // === Event Handlers ===

    function filterBySearch() {
      const query = searchInput.node().value.toLowerCase().trim();
      window.timelineSearchQuery = query;
      console.log('[Timeline] Search query:', query);
      renderScanTimelineD3();
    }

    searchInput.on("input", debounce(filterBySearch, 300));

    function parseDateInput(input) {
      if (!input) return null;

      // Try parsing common formats
      const formats = [
        // MM/DD/YYYY or M/D/YYYY
        /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/,
        // YYYY-MM-DD
        /^(\d{4})-(\d{1,2})-(\d{1,2})$/,
        // MM-DD-YYYY
        /^(\d{1,2})-(\d{1,2})-(\d{4})$/,
      ];

      for (const format of formats) {
        const match = input.trim().match(format);
        if (match) {
          let year, month, day;

          if (format === formats[0] || format === formats[2]) {
            // MM/DD/YYYY or MM-DD-YYYY
            [, month, day, year] = match;
          } else {
            // YYYY-MM-DD
            [, year, month, day] = match;
          }

          const date = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
          if (!isNaN(date.getTime())) {
            return date;
          }
        }
      }

      // Fallback to native Date parsing
      const date = new Date(input);
      return isNaN(date.getTime()) ? null : date;
    }

    function applyDateRange() {
      const startStr = startDateInput.node().value.trim();
      const endStr = endDateInput.node().value.trim();

      if (startStr && endStr) {
        const startDate = parseDateInput(startStr);
        const endDate = parseDateInput(endStr);

        if (startDate && endDate) {
          // Set to start of day for start date and end of day for end date
          startDate.setHours(0, 0, 0, 0);
          endDate.setHours(23, 59, 59, 999);

          window.timelineDateRange = {
            start: startDate,
            end: endDate
          };
          console.log('[Timeline] Date range set:', window.timelineDateRange);

          // Visual feedback
          startDateInput.style("border-color", colors.accent);
          endDateInput.style("border-color", colors.accent);

          renderScanTimelineD3();
        } else {
          console.warn('[Timeline] Invalid date format. Use MM/DD/YYYY or YYYY-MM-DD');
          showAlert('Invalid date format. Please use MM/DD/YYYY or YYYY-MM-DD', 'warning');

          // Visual feedback for error
          if (!startDate) startDateInput.style("border-color", "#dc3545");
          if (!endDate) endDateInput.style("border-color", "#dc3545");
        }
      } else if (!startStr && !endStr) {
        window.timelineDateRange = null;
        console.log('[Timeline] Date range cleared');
        renderScanTimelineD3();
      } else {
        showAlert('Please enter both start and end dates', 'warning');
      }
    }

    // Allow Enter key to apply date range
    startDateInput.on("keypress", function(event) {
      if (event.key === 'Enter') {
        applyDateRange();
      }
    });

    endDateInput.on("keypress", function(event) {
      if (event.key === 'Enter') {
        applyDateRange();
      }
    });

    // Export handlers
    setTimeout(() => {
      const exportSvgBtn = container.querySelector('.export-svg');
      const exportPngBtn = container.querySelector('.export-png');

      if (exportSvgBtn) {
        exportSvgBtn.addEventListener('click', (e) => {
          e.preventDefault();
          exportAsSVG(svg.node());
        });
      }

      if (exportPngBtn) {
        exportPngBtn.addEventListener('click', (e) => {
          e.preventDefault();
          exportAsPNG(svg.node());
        });
      }
    }, 100);

    updateLegend();
    console.log('[Timeline] Render complete');

    // Mark rendering complete and check for pending renders
    isRendering = false;
    if (pendingRender) {
      pendingRender = false;
      console.log('[Timeline] Executing queued render');
      setTimeout(() => renderScanTimelineD3(), 50);
    }
  }

  function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  function updateLegend() {
    const legend = document.getElementById("scanTimelineLegend");
    if (!legend) return;

    const colors = getColors();

    legend.innerHTML = `
      <span class="legend-item" role="listitem" title="CLI scans" style="margin-right:15px; display: inline-flex; align-items: center; gap: 6px;">
        <span style="background:${colors.cliScan}; width: 16px; height: 16px; border-radius: 4px; display: inline-block;"></span>
        <span style="font-size: 0.875rem; font-weight: 600; color: ${colors.text};">CLI</span>
      </span>
      <span class="legend-item" role="listitem" title="On-demand scans" style="margin-right:15px; display: inline-flex; align-items: center; gap: 6px;">
        <span style="background:${colors.ondemandScan}; width: 16px; height: 16px; border-radius: 4px; display: inline-block;"></span>
        <span style="font-size: 0.875rem; font-weight: 600; color: ${colors.text};">On-Demand</span>
      </span>
      <span class="legend-item" role="listitem" title="Completed" style="margin-right:15px; display: inline-flex; align-items: center; gap: 6px;">
        <span style="background:${colors.completed}; width: 16px; height: 16px; border-radius: 50%; display: inline-block;"></span>
        <span style="font-size: 0.875rem; font-weight: 600; color: ${colors.text};">Completed</span>
      </span>
      <span class="legend-item" role="listitem" title="Running" style="display: inline-flex; align-items: center; gap: 6px;">
        <span style="background:${colors.running}; width: 16px; height: 16px; border-radius: 50%; display: inline-block;"></span>
        <span style="font-size: 0.875rem; font-weight: 600; color: ${colors.text};">Running</span>
      </span>
    `;
  }

  // === Global Export ===

  window.renderScanTimelineD3 = renderScanTimelineD3;

  // === Auto-render ===

  document.addEventListener("DOMContentLoaded", () => {
    console.log('[Timeline] Auto-rendering on DOMContentLoaded');
    try {
      renderScanTimelineD3();
    } catch (e) {
      console.error("[Timeline] Render error:", e);
    }
  });

  // === Filter Sync ===

  document.addEventListener("change", (evt) => {
    if (evt.target.id === "timelineFilter" || evt.target.id === "scanSourceFilter") {
      console.log('[Timeline] Filter changed, re-rendering');
      try {
        renderScanTimelineD3();
      } catch (e) {
        console.error(e);
      }
    }
  });

  // Theme change listener
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.attributeName === 'class') {
        console.log('[Timeline] Theme changed, re-rendering');
        renderScanTimelineD3();
      }
    });
  });

  observer.observe(document.body, { attributes: true });

})();
