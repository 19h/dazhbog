//! Embedded HTML templates for the web dashboard.
//! AXIOM Design System - Industrial-Military Visual Language

/// Main dashboard HTML template.
pub const HOME: &str = r#"<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DAZHBOG // FUNCTION INDEX TERMINAL</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* ═══════════════════════════════════════════════════════════════
           AXIOM DESIGN SYSTEM - Industrial Military Visual Language
           Classification: OPERATIONAL // Document: DZB-SYS-001
           ═══════════════════════════════════════════════════════════════ */
        
        :root {
            /* Base Colors - Control Room Atmosphere */
            --bg-void: #050505;
            --bg-base: #0a0a0a;
            --bg-panel: #0f0f0f;
            --bg-element: #141414;
            --bg-elevated: #1a1a1a;
            
            /* Borders & Lines */
            --border-dim: #1f1f1f;
            --border-subtle: #2a2a2a;
            --border-focus: #3a3a3a;
            
            /* Primary Accent - Night Vision / Active Systems */
            --accent: #00ff88;
            --accent-dim: #00cc6a;
            --accent-glow: rgba(0, 255, 136, 0.15);
            --accent-pulse: rgba(0, 255, 136, 0.4);
            
            /* Text Hierarchy */
            --text-bright: #ffffff;
            --text-primary: #e8e8e8;
            --text-secondary: #a0a0a0;
            --text-tertiary: #666666;
            --text-dim: #444444;
            
            /* State Colors - Military Warning Palette */
            --state-nominal: #00ff88;
            --state-caution: #ffaa00;
            --state-warning: #ff6600;
            --state-critical: #ff2244;
            --state-info: #0088ff;
            
            /* Typography */
            --font-display: "Inter", -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: "JetBrains Mono", "SF Mono", "Consolas", monospace;
            
            /* Spacing Scale */
            --space-xs: 4px;
            --space-sm: 8px;
            --space-md: 16px;
            --space-lg: 24px;
            --space-xl: 32px;
            --space-2xl: 48px;
            
            /* Animation */
            --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
            --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
        }
        
        /* ─────────────────────────────────────────────────────────────
           BASE RESET & DOCUMENT
           ───────────────────────────────────────────────────────────── */
        
        *, *::before, *::after { box-sizing: border-box; }
        
        body {
            margin: 0;
            background: var(--bg-void);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 13px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Scanline overlay effect */
        body::before {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(0, 0, 0, 0.03) 2px,
                rgba(0, 0, 0, 0.03) 4px
            );
            pointer-events: none;
            z-index: 9999;
        }
        
        /* ─────────────────────────────────────────────────────────────
           DIAGONAL STRIPE PATTERNS
           ───────────────────────────────────────────────────────────── */
        
        .stripe-pattern {
            background: repeating-linear-gradient(
                -45deg,
                transparent,
                transparent 4px,
                var(--border-dim) 4px,
                var(--border-dim) 5px
            );
        }
        
        .stripe-accent {
            background: repeating-linear-gradient(
                -45deg,
                transparent,
                transparent 3px,
                var(--accent) 3px,
                var(--accent) 4px
            );
            opacity: 0.15;
        }
        
        /* ─────────────────────────────────────────────────────────────
           DOT GRID PATTERN
           ───────────────────────────────────────────────────────────── */
        
        .dot-grid {
            background-image: radial-gradient(circle, var(--border-subtle) 1px, transparent 1px);
            background-size: 16px 16px;
        }
        
        /* ─────────────────────────────────────────────────────────────
           MAIN CONTAINER
           ───────────────────────────────────────────────────────────── */
        
        .terminal-frame {
            max-width: 1400px;
            margin: 0 auto;
            padding: var(--space-lg);
            position: relative;
        }
        
        /* Corner registration marks */
        .terminal-frame::before,
        .terminal-frame::after {
            content: "";
            position: absolute;
            width: 24px;
            height: 24px;
            border-color: var(--border-subtle);
            border-style: solid;
        }
        .terminal-frame::before {
            top: 8px;
            left: 8px;
            border-width: 2px 0 0 2px;
        }
        .terminal-frame::after {
            top: 8px;
            right: 8px;
            border-width: 2px 2px 0 0;
        }
        
        /* ─────────────────────────────────────────────────────────────
           HEADER - CLASSIFICATION BANNER
           ───────────────────────────────────────────────────────────── */
        
        .classification-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-xs) var(--space-md);
            background: var(--accent);
            color: var(--bg-void);
            font-family: var(--font-mono);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            margin-bottom: var(--space-md);
        }
        
        .classification-bar .doc-code {
            font-weight: 600;
            letter-spacing: 0.1em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           MAIN HEADER
           ───────────────────────────────────────────────────────────── */
        
        .header-grid {
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            gap: var(--space-lg);
            align-items: start;
            padding: var(--space-lg) 0;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .header-left {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
        }
        
        .brand-block {
            display: flex;
            align-items: center;
            gap: var(--space-md);
        }
        
        .brand-icon {
            width: 48px;
            height: 48px;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .brand-icon .ring {
            position: absolute;
            border: 2px solid var(--accent);
            border-radius: 50%;
        }
        .brand-icon .ring-outer {
            width: 48px;
            height: 48px;
        }
        .brand-icon .ring-inner {
            width: 32px;
            height: 32px;
        }
        .brand-icon .core {
            width: 12px;
            height: 12px;
            background: var(--accent);
            border-radius: 50%;
            box-shadow: 0 0 20px var(--accent-pulse);
            animation: core-pulse 2s ease-in-out infinite;
        }
        
        @keyframes core-pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(0.9); }
        }
        
        .brand-text {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .brand-name {
            font-family: var(--font-display);
            font-size: 28px;
            font-weight: 900;
            letter-spacing: 0.08em;
            color: var(--text-bright);
            line-height: 1;
        }
        
        .brand-sub {
            font-size: 10px;
            color: var(--text-tertiary);
            letter-spacing: 0.2em;
            text-transform: uppercase;
        }
        
        .serial-block {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .serial-block span {
            display: flex;
            gap: var(--space-sm);
        }
        
        .serial-block .label {
            color: var(--text-tertiary);
            min-width: 60px;
        }
        
        /* Center status ring */
        .header-center {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: var(--space-sm);
        }
        
        .status-ring {
            width: 80px;
            height: 80px;
            border: 3px solid var(--border-subtle);
            border-radius: 50%;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .status-ring::before {
            content: "";
            position: absolute;
            inset: 6px;
            border: 1px solid var(--border-dim);
            border-radius: 50%;
        }
        
        .status-ring .status-core {
            width: 24px;
            height: 24px;
            background: var(--state-nominal);
            border-radius: 50%;
            box-shadow: 0 0 30px var(--accent-pulse), inset 0 0 10px rgba(255,255,255,0.3);
            animation: status-pulse 1.5s ease-in-out infinite;
        }
        
        .status-ring.offline .status-core {
            background: var(--state-critical);
            box-shadow: 0 0 30px rgba(255, 34, 68, 0.4);
            animation: none;
        }
        
        @keyframes status-pulse {
            0%, 100% { box-shadow: 0 0 30px var(--accent-pulse), inset 0 0 10px rgba(255,255,255,0.3); }
            50% { box-shadow: 0 0 50px var(--accent-pulse), inset 0 0 15px rgba(255,255,255,0.5); }
        }
        
        .status-label {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--accent);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }
        
        .status-label::before,
        .status-label::after {
            content: "//";
            color: var(--text-dim);
        }
        
        .status-label.offline {
            color: var(--state-critical);
        }
        
        /* Right side - coordinates and timestamp */
        .header-right {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: var(--space-sm);
            text-align: right;
        }
        
        .coord-block {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        
        .timestamp-block {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }
        
        .uptime-block {
            font-size: 10px;
            color: var(--text-tertiary);
            letter-spacing: 0.1em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           SEARCH TERMINAL
           ───────────────────────────────────────────────────────────── */
        
        .search-terminal {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            padding: var(--space-lg);
            margin-bottom: var(--space-xl);
            position: relative;
        }
        
        .search-terminal::before {
            content: "QUERY INTERFACE";
            position: absolute;
            top: -8px;
            left: var(--space-md);
            background: var(--bg-panel);
            padding: 0 var(--space-sm);
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
        }
        
        .search-row {
            display: flex;
            gap: var(--space-md);
            align-items: center;
        }

        .search-mode-switch {
            display: inline-flex;
            align-items: center;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-dim);
        }

        .search-mode-btn {
            background: transparent;
            border: 0;
            color: var(--text-dim);
            padding: 10px 14px;
            font-family: var(--font-mono);
            font-size: 11px;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            cursor: pointer;
        }

        .search-mode-btn.active {
            color: var(--bg-base);
            background: var(--accent);
        }
        
        .search-prompt {
            font-size: 14px;
            font-weight: 700;
            color: var(--accent);
            white-space: nowrap;
        }
        
        .search-input-wrap {
            flex: 1;
            position: relative;
        }
        
        .search-input {
            width: 100%;
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            padding: var(--space-md) var(--space-lg);
            font-family: var(--font-mono);
            font-size: 14px;
            color: var(--text-primary);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        
        .search-input::placeholder {
            color: var(--text-dim);
        }
        
        .search-input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow), inset 0 0 20px rgba(0, 255, 136, 0.03);
        }
        
        .search-kbd {
            position: absolute;
            right: var(--space-md);
            top: 50%;
            transform: translateY(-50%);
            font-size: 10px;
            font-weight: 600;
            color: var(--text-dim);
            border: 1px solid var(--border-dim);
            padding: 2px 8px;
            letter-spacing: 0.1em;
        }
        
        .search-meta {
            display: flex;
            gap: var(--space-lg);
            margin-top: var(--space-md);
            padding-top: var(--space-md);
            border-top: 1px dashed var(--border-dim);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .search-meta span {
            display: flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .search-meta .accent {
            color: var(--accent);
        }
        
        /* ─────────────────────────────────────────────────────────────
           METRICS GRID - OPERATIONAL DASHBOARD
           ───────────────────────────────────────────────────────────── */
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .dashboard-grid.hidden { display: none; }
        
        .metric-section-header {
            grid-column: 1 / -1;
            background: var(--bg-element);
            padding: var(--space-sm) var(--space-md);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        
        .metric-section-header .section-code {
            color: var(--text-dim);
            font-weight: 400;
        }
        
        .metric-card {
            background: var(--bg-panel);
            padding: var(--space-lg);
            display: flex;
            flex-direction: column;
            gap: var(--space-xs);
            position: relative;
        }
        
        .metric-card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 3px;
            height: 100%;
            background: var(--border-subtle);
        }
        
        .metric-card.nominal::before { background: var(--state-nominal); }
        .metric-card.caution::before { background: var(--state-caution); }
        .metric-card.warning::before { background: var(--state-warning); }
        .metric-card.critical::before { background: var(--state-critical); }
        
        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }
        
        .metric-label {
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
            text-transform: uppercase;
        }
        
        .metric-code {
            font-size: 9px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .metric-value {
            font-size: 32px;
            font-weight: 700;
            color: var(--text-bright);
            font-variant-numeric: tabular-nums;
            line-height: 1;
            margin: var(--space-sm) 0;
        }
        
        .metric-card.nominal .metric-value { color: var(--state-nominal); }
        .metric-card.critical .metric-value { color: var(--state-critical); }
        .metric-card.warning .metric-value { color: var(--state-warning); }
        
        .metric-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-top: var(--space-sm);
            border-top: 1px dashed var(--border-dim);
        }
        
        .metric-sub {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.05em;
        }
        
        .metric-indicator {
            display: flex;
            gap: 2px;
        }
        
        .metric-indicator .bar {
            width: 3px;
            height: 12px;
            background: var(--border-dim);
        }
        
        .metric-indicator .bar.active { background: var(--accent); }
        .metric-indicator .bar.warn { background: var(--state-warning); }
        .metric-indicator .bar.crit { background: var(--state-critical); }
        
        /* Span two columns */
        .metric-wide {
            grid-column: span 2;
        }
        
        /* ─────────────────────────────────────────────────────────────
           SECONDARY METRICS ROW
           ───────────────────────────────────────────────────────────── */
        
        .metrics-secondary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-xl);
        }
        
        .metrics-secondary.hidden { display: none; }
        
        .metric-mini {
            background: var(--bg-panel);
            padding: var(--space-md);
            text-align: center;
        }
        
        .metric-mini .label {
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-dim);
            text-transform: uppercase;
            margin-bottom: var(--space-xs);
        }
        
        .metric-mini .value {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }

        .metric-rate {
            margin-top: 4px;
            font-size: 9px;
            color: var(--text-tertiary);
            letter-spacing: 0.06em;
            min-height: 1em;
        }

        .sparkline {
            margin-top: 4px;
            font-size: 11px;
            color: var(--text-tertiary);
            font-family: var(--font-mono);
            letter-spacing: 1px;
            min-height: 1em;
        }
        
        .metric-mini.error .value { color: var(--state-critical); }
        .metric-mini.warn .value { color: var(--state-warning); }
        
        /* ─────────────────────────────────────────────────────────────
           RESULTS CONTAINER
           ───────────────────────────────────────────────────────────── */
        
        .results-container {
            display: none;
        }
        
        .results-container.active {
            display: block;
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: var(--space-md);
            padding: var(--space-md);
            background: var(--bg-element);
            border: 1px solid var(--border-subtle);
            border-bottom: none;
        }

        .results-header-main {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            min-width: 0;
        }
        
        .results-title {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: var(--space-md);
        }

        .results-intent {
            font-size: 10px;
            color: var(--accent);
            letter-spacing: 0.1em;
            border: 1px solid rgba(0, 255, 136, 0.4);
            padding: 2px 6px;
            background: rgba(0, 255, 136, 0.1);
        }

        .results-hint {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.08em;
            text-transform: none;
        }
        
        .results-count {
            background: var(--accent);
            color: var(--bg-void);
            padding: 2px 8px;
            font-size: 10px;
            font-weight: 700;
        }

        .results-total {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }

        .results-meta {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            display: flex;
            gap: var(--space-lg);
            flex-wrap: wrap;
        }

        .results-tools {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            align-items: flex-end;
        }

        .sort-controls {
            display: flex;
            align-items: center;
            gap: var(--space-sm);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }

        .sort-controls select {
            background: var(--bg-panel);
            color: var(--text-secondary);
            border: 1px solid var(--border-subtle);
            font-family: var(--font-mono);
            font-size: 11px;
            padding: 4px 8px;
        }

        .sort-controls select:focus {
            outline: none;
            border-color: var(--accent);
        }

        .compare-panel {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            margin: var(--space-lg) 0 var(--space-xl);
            border: 1px solid var(--border-subtle);
            background: linear-gradient(180deg, rgba(255,255,255,0.01), rgba(255,255,255,0.02));
            padding: var(--space-md);
        }

        .compare-panel.hidden {
            display: none;
        }

        .compare-panel.compact {
            padding: 10px 12px;
        }

        .compare-panel-head {
            display: flex;
            align-items: center;
            gap: var(--space-md);
            flex-wrap: wrap;
            min-width: 0;
        }

        .compare-panel .compare-title {
            color: var(--accent);
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }

        .compare-panel-summary {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.08em;
        }

        .compare-panel-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .compare-panel-actions select {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 5px 8px;
        }

        .compare-panel-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            width: 100%;
        }

        .compare-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            border: 1px solid rgba(0, 255, 136, 0.25);
            background: rgba(0, 255, 136, 0.08);
            padding: 6px 8px;
            min-width: 0;
            max-width: 100%;
        }

        .compare-pill.loading {
            border-style: dashed;
            opacity: 0.78;
        }

        .compare-pill.baseline {
            border-color: rgba(255, 170, 0, 0.45);
            background: rgba(255, 170, 0, 0.08);
        }

        .compare-pill.dragging {
            opacity: 0.5;
        }

        .compare-pill-handle,
        .compare-pill-pin {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 3px 6px;
            cursor: grab;
        }

        .compare-pill-pin {
            cursor: pointer;
        }

        .compare-pill-pin.active {
            color: var(--state-warning);
            border-color: rgba(255, 170, 0, 0.45);
        }

        .compare-pill-main {
            display: flex;
            flex-direction: column;
            gap: 2px;
            min-width: 0;
        }

        .compare-pill-name {
            color: var(--accent);
            font-size: 11px;
            font-weight: 600;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 320px;
        }

        .compare-pill-key {
            color: var(--text-tertiary);
            font-size: 9px;
            font-family: var(--font-mono);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            max-width: 320px;
        }

        .compare-pill-status {
            color: var(--text-dim);
            font-size: 9px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .compare-pill-remove {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 3px 7px;
            cursor: pointer;
        }

        .compare-pill-remove:hover {
            color: var(--state-warning);
            border-color: rgba(255, 102, 0, 0.4);
        }
        
        .results-list {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
        }
        
        .result-item {
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: var(--space-lg);
            padding: var(--space-lg);
            border-bottom: 1px solid var(--border-dim);
            transition: background 0.1s;
            position: relative;
        }
        
        .result-item:last-child {
            border-bottom: none;
        }
        
        .result-item:hover {
            background: var(--bg-element);
        }

        .result-item.selected {
            background: rgba(0, 255, 136, 0.07);
            box-shadow: inset 3px 0 0 var(--accent);
        }
        
        .result-index {
            font-size: 10px;
            font-weight: 700;
            color: var(--text-dim);
            padding: var(--space-xs) var(--space-sm);
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            height: fit-content;
            min-width: 36px;
            text-align: center;
        }
        
        .result-main {
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
            min-width: 0;
        }
        
        .result-func {
            font-size: 14px;
            font-weight: 600;
            color: var(--accent);
            word-break: break-all;
            line-height: 1.4;
        }

        .result-func .type-compact-token,
        .comment-item-text .type-compact-token {
            font-size: inherit;
        }
        
        .result-key {
            font-size: 11px;
            color: var(--text-dim);
            font-family: var(--font-mono);
            display: flex;
            align-items: center;
            gap: var(--space-sm);
        }

        .result-key-copy {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 3px 6px;
            border: 1px solid transparent;
            cursor: copy;
            transition: background 120ms ease, border-color 120ms ease, color 120ms ease;
        }

        .result-key-copy:hover,
        .result-key-copy.copied {
            background: rgba(0, 255, 136, 0.08);
            border-color: rgba(0, 255, 136, 0.35);
            color: var(--accent);
        }

        .result-key-copy::after {
            content: "click to copy";
            font-size: 9px;
            letter-spacing: 0.08em;
            color: var(--text-tertiary);
            text-transform: uppercase;
        }

        .result-key-copy.copied::after {
            content: "copied";
            color: var(--accent);
        }

        .result-age {
            color: var(--text-tertiary);
            font-size: 10px;
            letter-spacing: 0.08em;
        }
        
        .result-mangled {
            font-size: 10px;
            color: var(--text-tertiary);
            font-family: var(--font-mono);
            word-break: break-all;
            line-height: 1.3;
            margin-top: 2px;
            padding: 4px 6px;
            background: rgba(0, 0, 0, 0.3);
            border-left: 2px solid var(--text-tertiary);
            max-height: 40px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .result-mangled:hover {
            max-height: none;
            background: rgba(0, 0, 0, 0.5);
        }
        
        .lang-badge {
            font-size: 9px;
            font-weight: 700;
            color: var(--bg-void);
            background: var(--state-info);
            padding: 2px 6px;
            letter-spacing: 0.1em;
        }
        
        .result-bins {
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-xs);
            margin-top: var(--space-xs);
        }
        
        .bin-tag {
            font-size: 10px;
            color: var(--state-info);
            background: rgba(0, 136, 255, 0.1);
            border: 1px solid rgba(0, 136, 255, 0.2);
            padding: 2px 8px;
            letter-spacing: 0.05em;
        }

        .bin-tag.clickable {
            cursor: pointer;
        }

        .bin-tag.clickable:hover {
            border-color: rgba(0, 255, 136, 0.45);
            color: var(--text-primary);
        }

        .binary-graph {
            position: relative;
            min-height: 360px;
            border: 1px solid var(--border-dim);
            background:
                radial-gradient(circle at top, rgba(0,255,136,0.06), transparent 42%),
                linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0));
            overflow: hidden;
        }

        .binary-graph-stage {
            position: absolute;
            inset: 0;
            transform-origin: center center;
            transition: transform 140ms ease;
        }

        .binary-graph-controls {
            display: inline-flex;
            gap: 8px;
            align-items: center;
            margin-left: auto;
            flex: 0 0 auto;
        }

        .binary-graph-toolbar {
            display: grid;
            grid-template-columns: repeat(2, minmax(120px, 260px)) auto 1fr;
            gap: 12px 16px;
            align-items: end;
            margin-bottom: var(--space-md);
        }

        .binary-graph-field {
            display: grid;
            gap: 6px;
        }

        .neighbor-toggle {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            min-height: 40px;
            padding: 8px 12px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            cursor: pointer;
            transition: border-color 0.16s ease, color 0.16s ease, background 0.16s ease, box-shadow 0.16s ease;
        }

        .neighbor-toggle:hover {
            border-color: rgba(0, 255, 136, 0.22);
            color: var(--text-primary);
        }

        .neighbor-toggle.active {
            border-color: rgba(0, 255, 136, 0.34);
            color: var(--accent);
            background: rgba(0, 255, 136, 0.08);
            box-shadow: inset 0 0 0 1px rgba(0, 255, 136, 0.08);
        }

        .neighbor-toggle-track {
            width: 42px;
            height: 22px;
            border-radius: 999px;
            border: 1px solid var(--border-focus);
            background: rgba(255, 255, 255, 0.04);
            position: relative;
            transition: border-color 0.16s ease, background 0.16s ease;
            flex: 0 0 auto;
        }

        .neighbor-toggle.active .neighbor-toggle-track {
            border-color: rgba(0, 255, 136, 0.38);
            background: rgba(0, 255, 136, 0.18);
        }

        .neighbor-toggle-thumb {
            position: absolute;
            top: 2px;
            left: 2px;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            background: var(--text-secondary);
            box-shadow: 0 0 0 1px rgba(255, 255, 255, 0.05);
            transition: transform 0.16s ease, background 0.16s ease;
        }

        .neighbor-toggle.active .neighbor-toggle-thumb {
            transform: translateX(20px);
            background: var(--accent);
        }

        .neighbor-toggle-copy {
            display: inline-flex;
            flex-direction: column;
            gap: 2px;
            text-align: left;
        }

        .neighbor-toggle-copy .secondary {
            color: var(--text-dim);
            font-size: 9px;
            letter-spacing: 0.16em;
        }

        .neighbor-toggle.active .neighbor-toggle-copy .secondary {
            color: rgba(0, 255, 136, 0.7);
        }

        .neighbor-results {
            display: grid;
            gap: var(--space-sm);
        }

        .neighbor-card {
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            padding: 14px 16px;
            display: grid;
            gap: 10px;
            transition: border-color 0.16s ease, background 0.16s ease, transform 0.16s ease;
        }

        .neighbor-card:hover {
            border-color: rgba(0, 255, 136, 0.18);
            background: var(--bg-element);
        }

        .neighbor-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 16px;
        }

        .neighbor-card-main {
            min-width: 0;
            display: grid;
            gap: 6px;
        }

        .neighbor-card-link {
            display: grid;
            gap: 6px;
            color: inherit;
            text-decoration: none;
            min-width: 0;
        }

        .neighbor-card-main.clickable {
            cursor: pointer;
        }

        .neighbor-card-main.clickable:hover .neighbor-card-title,
        .neighbor-card-link:hover .neighbor-card-title {
            text-shadow: 0 0 12px rgba(0, 255, 136, 0.16);
        }

        .neighbor-card-title {
            color: var(--accent);
            font-size: 14px;
            font-weight: 600;
            line-height: 1.4;
            overflow-wrap: anywhere;
        }

        .neighbor-card-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px 12px;
            color: var(--text-dim);
            font-size: 11px;
        }

        .neighbor-card-key {
            color: var(--text-tertiary);
            font-size: 10px;
            letter-spacing: 0.08em;
            overflow-wrap: anywhere;
        }

        .detail-name-stack {
            display: grid;
            gap: 8px;
        }

        .detail-name-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }

        .neighbor-card-actions {
            display: grid;
            justify-items: end;
            gap: 8px;
            flex: 0 0 auto;
        }

        .neighbor-pill-row {
            display: flex;
            flex-wrap: wrap;
            justify-content: flex-end;
            gap: 6px;
        }

        .neighbor-pill {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            border: 1px solid var(--border-dim);
            background: rgba(255, 255, 255, 0.02);
            color: var(--text-secondary);
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            white-space: nowrap;
        }

        .neighbor-pill.accent {
            border-color: rgba(0, 255, 136, 0.3);
            background: rgba(0, 255, 136, 0.08);
            color: var(--accent);
        }

        .neighbor-pill.info {
            border-color: rgba(0, 136, 255, 0.28);
            background: rgba(0, 136, 255, 0.1);
            color: var(--state-info);
        }

        .neighbor-pill.warn {
            border-color: rgba(255, 170, 0, 0.28);
            background: rgba(255, 170, 0, 0.1);
            color: var(--state-caution);
        }

        .neighbor-rationale {
            border-top: 1px solid var(--border-dim);
            padding-top: 10px;
        }

        .neighbor-rationale summary {
            list-style: none;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
            cursor: pointer;
            color: var(--text-secondary);
            user-select: none;
        }

        .neighbor-rationale summary::-webkit-details-marker {
            display: none;
        }

        .neighbor-rationale summary::before {
            content: ">";
            color: var(--text-dim);
            transition: transform 0.14s ease;
        }

        .neighbor-rationale[open] summary::before {
            transform: rotate(90deg);
            color: var(--accent);
        }

        .neighbor-rationale-title {
            font-size: 10px;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            color: var(--text-tertiary);
        }

        .neighbor-rationale-content {
            display: grid;
            gap: 12px;
            margin-top: 12px;
        }

        .neighbor-rationale-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(96px, 1fr));
            gap: 8px;
        }

        .neighbor-metric {
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            padding: 10px 12px;
            min-width: 0;
        }

        .neighbor-metric .label {
            font-size: 9px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--text-dim);
            margin-bottom: 6px;
        }

        .neighbor-metric .value {
            font-size: 16px;
            font-weight: 700;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }

        .binary-graph-hint {
            grid-column: 1 / -1;
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        .binary-graph-view-switch {
            display: inline-flex;
            gap: 8px;
            margin-left: 12px;
        }

        .binary-graph svg {
            position: absolute;
            inset: 0;
            width: 100%;
            height: 100%;
        }

        .binary-graph-node {
            position: absolute;
            width: 132px;
            transform: translate(-50%, -50%);
            border: 1px solid var(--border-dim);
            background: rgba(12, 16, 18, 0.92);
            padding: 8px 10px;
            cursor: pointer;
            box-shadow: 0 18px 40px rgba(0, 0, 0, 0.3);
            transition: transform 0.16s ease, border-color 0.16s ease, opacity 0.16s ease;
        }

        .binary-graph-node.root {
            border-color: rgba(0,255,136,0.45);
            box-shadow: 0 0 0 1px rgba(0,255,136,0.25), 0 18px 40px rgba(0, 0, 0, 0.3);
        }

        .binary-graph-node.dimmed {
            opacity: 0.34;
        }

        .binary-graph-node.highlighted {
            transform: translate(-50%, -50%) scale(1.03);
            border-color: rgba(0,255,136,0.55);
            z-index: 3;
        }

        .binary-graph-node.compact {
            width: 92px;
            padding: 6px 8px;
            background: rgba(10, 12, 14, 0.82);
            z-index: 1;
        }

        .binary-graph-node.compact .binary-graph-node-actions,
        .binary-graph-node.compact .coverage-strip {
            display: none;
        }

        .binary-graph-node-actions {
            display: flex;
            gap: 6px;
            margin-top: 8px;
        }

        .binary-graph-node-actions button {
            flex: 1;
        }

        .binary-graph line.dimmed {
            opacity: 0.16;
        }

        .binary-graph line.highlighted {
            opacity: 1;
        }

        .binary-graph-node .name {
            font-size: 11px;
            color: var(--text-primary);
            margin-bottom: 4px;
            line-height: 1.25;
            word-break: break-word;
        }

        .binary-graph-node .meta {
            font-size: 9px;
            color: var(--text-dim);
            letter-spacing: 0.08em;
        }

        .binary-coverage-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: var(--space-sm);
        }

        .coverage-card {
            border: 1px solid var(--border-dim);
            background: rgba(255,255,255,0.02);
            padding: 10px 12px;
        }

        .coverage-card .label {
            font-size: 10px;
            letter-spacing: 0.1em;
            color: var(--text-dim);
            margin-bottom: 6px;
        }

        .coverage-card .value {
            font-size: 18px;
            color: var(--text-primary);
        }

        .binary-compare-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: var(--space-md);
            margin-bottom: var(--space-md);
        }

        .compare-list-grid {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: var(--space-md);
        }

        .compare-list-column {
            border: 1px solid var(--border-dim);
            background: rgba(255,255,255,0.02);
            padding: 10px 12px;
        }

        .compare-mode-switch {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: var(--space-md);
        }

        .compare-toolbar {
            display: grid;
            gap: var(--space-md);
            margin-bottom: var(--space-md);
        }

        .compare-toolbar-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: end;
        }

        .compare-field {
            display: grid;
            gap: 6px;
            min-width: 140px;
        }

        .compare-field input {
            width: 100%;
        }

        .compare-search-row {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: end;
            margin-bottom: var(--space-md);
        }

        .compare-item-row {
            display: grid;
            grid-template-columns: minmax(0, 1fr) auto;
            gap: 12px;
            align-items: start;
            padding: 10px 12px;
            border-top: 1px solid var(--border-subtle);
            cursor: pointer;
        }

        .compare-item-row:first-of-type {
            border-top: 0;
        }

        .compare-item-main {
            min-width: 0;
            display: grid;
            gap: 6px;
        }

        .compare-item-name {
            color: var(--text-primary);
            line-height: 1.45;
            overflow-wrap: anywhere;
            word-break: break-word;
        }

        .compare-item-meta {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
        }

        .compare-item-age {
            color: var(--text-tertiary);
            font-size: 10px;
            letter-spacing: 0.08em;
            white-space: nowrap;
            padding-top: 2px;
        }

        .preset-note {
            margin-top: 6px;
            font-size: 10px;
            letter-spacing: 0.05em;
            color: var(--text-dim);
            border-left: 2px solid rgba(0,255,136,0.28);
            padding-left: 10px;
        }

        .workbench-layout {
            display: grid;
            grid-template-columns: 320px minmax(0, 1fr) 320px;
            gap: var(--space-md);
            align-items: start;
        }

        .workbench-side {
            position: sticky;
            top: var(--space-md);
            border: 1px solid var(--border-dim);
            background: rgba(255,255,255,0.02);
            padding: 12px;
        }

        .workbench-center {
            min-width: 0;
        }

        .coverage-strip {
            display: grid;
            gap: 6px;
            margin-top: 10px;
        }

        .coverage-strip-row {
            display: grid;
            grid-template-columns: 88px 1fr 44px;
            gap: 8px;
            align-items: center;
            font-size: 10px;
            color: var(--text-dim);
        }

        .coverage-strip-bar {
            height: 6px;
            border: 1px solid var(--border-dim);
            background: rgba(255,255,255,0.03);
            position: relative;
            overflow: hidden;
        }

        .coverage-strip-fill {
            position: absolute;
            inset: 0 auto 0 0;
            background: rgba(0,255,136,0.82);
        }

        .detail-note {
            margin-top: 8px;
            color: var(--text-dim);
            font-size: 11px;
            line-height: 1.5;
            max-width: 78ch;
        }

        .timeline-stack {
            display: grid;
            gap: var(--space-sm);
        }

        .timeline-row,
        .related-binary-row {
            display: grid;
            grid-template-columns: minmax(280px, 1fr) minmax(320px, 520px) 180px;
            gap: var(--space-md);
            align-items: center;
            border: 1px solid var(--border-dim);
            background: rgba(255,255,255,0.02);
            padding: 12px 14px;
            transition: border-color 160ms var(--ease-out), background 160ms var(--ease-out), transform 160ms var(--ease-out), box-shadow 160ms var(--ease-out);
        }

        .timeline-row.clickable,
        .related-binary-row.clickable {
            cursor: pointer;
        }

        .timeline-row.clickable:hover,
        .related-binary-row.clickable:hover {
            background: rgba(0,255,136,0.05);
            border-color: rgba(0,255,136,0.35);
            box-shadow: inset 0 0 0 1px rgba(0,255,136,0.12);
            transform: translateX(2px);
        }

        .timeline-row.clickable:hover .detail-value,
        .related-binary-row.clickable:hover .detail-value {
            color: var(--text-bright);
            text-shadow: 0 0 14px rgba(0,255,136,0.18);
        }

        .timeline-row.clickable:hover .timeline-metric-label,
        .related-binary-row.clickable:hover .related-binary-meta,
        .related-binary-row.clickable:hover .related-binary-stat,
        .related-binary-row.clickable:hover .related-overlap-label {
            color: var(--text-secondary);
        }

        .timeline-metrics {
            display: grid;
            gap: 8px;
            align-content: center;
        }

        .timeline-metric-row {
            display: grid;
            grid-template-columns: 220px 1fr;
            gap: 10px;
            align-items: center;
        }

        .timeline-metric-label {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
        }

        .timeline-meta {
            display: grid;
            justify-items: end;
            align-content: center;
            gap: 8px;
        }

        .related-binary-main {
            min-width: 0;
            display: grid;
            align-content: center;
            gap: 6px;
        }

        .binary-name-row {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .binary-title {
            margin: 0;
            line-height: 1.2;
        }

        .binary-short-id {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            border: 1px solid rgba(0, 255, 136, 0.28);
            background: rgba(0, 255, 136, 0.08);
            color: var(--accent);
            font-size: 11px;
            letter-spacing: 0.08em;
            line-height: 1;
            text-transform: uppercase;
        }

        .related-binary-meta {
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.08em;
        }

        .related-binary-side {
            display: grid;
            justify-items: end;
            gap: 8px;
        }

        .related-binary-stat {
            display: grid;
            justify-items: end;
            gap: 4px;
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.08em;
        }

        .related-overlap-grid {
            width: 100%;
            display: grid;
            gap: 8px;
        }

        .related-overlap-row {
            display: grid;
            grid-template-columns: 190px minmax(0, 1fr);
            gap: 10px;
            align-items: center;
        }

        .related-overlap-label {
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            text-align: right;
            white-space: nowrap;
        }

        .binary-overlap-actions {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            flex-wrap: wrap;
        }

        .timeline-bar {
            position: relative;
            height: 8px;
            border: 1px solid var(--border-dim);
            background: rgba(255,255,255,0.03);
            overflow: hidden;
        }

        .timeline-bar-fill {
            position: absolute;
            inset: 0 auto 0 0;
            background: rgba(0,255,136,0.82);
        }
        
        .result-meta {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: var(--space-xs);
            text-align: right;
        }

        .score-meter {
            width: 110px;
            height: 5px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            position: relative;
            overflow: hidden;
        }

        .score-meter-fill {
            position: absolute;
            top: 0;
            left: 0;
            bottom: 0;
            background: linear-gradient(90deg, var(--accent-dim), var(--accent));
        }

        .result-actions {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .result-action {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 9px;
            letter-spacing: 0.08em;
            padding: 2px 6px;
            cursor: pointer;
            text-transform: uppercase;
        }

        .result-action:hover {
            border-color: var(--accent);
            color: var(--accent);
        }

        .result-action.active {
            border-color: var(--accent);
            color: var(--bg-void);
            background: var(--accent);
        }

        .result-preview {
            grid-column: 1 / -1;
            margin-top: var(--space-sm);
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            padding: var(--space-sm);
            display: none;
        }

        .result-preview.active {
            display: block;
        }

        .result-preview-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-sm);
        }

        .result-preview-stat {
            background: var(--bg-panel);
            padding: 6px 8px;
            min-width: 0;
        }

        .result-preview-stat .label {
            font-size: 9px;
            letter-spacing: 0.08em;
            color: var(--text-dim);
            text-transform: uppercase;
        }

        .result-preview-stat .value {
            margin-top: 2px;
            font-size: 11px;
            color: var(--text-secondary);
            font-family: var(--font-mono);
            overflow-wrap: anywhere;
        }

        .result-preview-line {
            font-size: 11px;
            color: var(--text-dim);
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .result-preview-line .k {
            color: var(--text-tertiary);
            text-transform: uppercase;
            font-size: 9px;
            letter-spacing: 0.08em;
            margin-right: 6px;
        }
        
        .version-badge {
            font-size: 10px;
            font-weight: 700;
            color: var(--bg-void);
            background: var(--accent);
            padding: 2px 8px;
            letter-spacing: 0.1em;
        }

        .version-badge.age {
            background: rgba(0, 255, 136, 0.12);
            color: var(--accent);
            border: 1px solid rgba(0, 255, 136, 0.35);
        }
        
        .score-badge {
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.05em;
        }
        
        /* ─────────────────────────────────────────────────────────────
           PAGINATION CONTROLS
           ───────────────────────────────────────────────────────────── */

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: var(--space-sm);
            padding: var(--space-lg);
            border-top: 1px solid var(--border-dim);
            background: var(--bg-element);
        }

        .pagination-btn {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            padding: var(--space-sm) var(--space-md);
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.1em;
            cursor: pointer;
            transition: all 0.15s;
        }

        .pagination-btn:hover:not(:disabled) {
            border-color: var(--accent);
            color: var(--accent);
            background: var(--accent-glow);
        }

        .pagination-btn:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }

        .pagination-info {
            font-size: 11px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
            padding: 0 var(--space-md);
        }

        .pagination-info .accent {
            color: var(--accent);
            font-weight: 600;
        }

        /* ─────────────────────────────────────────────────────────────
           DETAIL PAGES
           ───────────────────────────────────────────────────────────── */

        .detail-page-shell {
            margin-top: var(--space-lg);
        }

        .page-panel {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
            min-width: 0;
            overflow: visible;
        }

        .detail-page-shell .modal-body {
            overflow: visible;
            min-height: auto;
        }

        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.85);
            z-index: 10000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: var(--space-lg);
            overflow: hidden;
        }

        .modal-overlay.active {
            display: flex;
        }

        .modal-container {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            width: min(1040px, calc(100vw - (var(--space-lg) * 2)));
            max-height: min(90vh, calc(100dvh - (var(--space-lg) * 2)));
            overflow: hidden;
            display: flex;
            flex-direction: column;
            position: relative;
            box-shadow: 0 24px 80px rgba(0, 0, 0, 0.5);
        }

        .page-panel.compare-panel-page {
            width: 100%;
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            padding: var(--space-md) var(--space-lg);
            background: var(--bg-element);
            border-bottom: 1px solid var(--border-subtle);
            flex: 0 0 auto;
        }

        .modal-title {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.2em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            min-width: 0;
            overflow-wrap: anywhere;
        }

        .modal-close {
            background: transparent;
            border: 1px solid var(--border-subtle);
            color: var(--text-secondary);
            width: 32px;
            height: 32px;
            font-size: 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.15s;
        }

        .modal-close:hover {
            border-color: var(--state-critical);
            color: var(--state-critical);
            background: rgba(255, 34, 68, 0.1);
        }

        .modal-body {
            padding: var(--space-lg);
            overflow-y: auto;
            flex: 1;
            min-height: 0;
            overscroll-behavior: contain;
        }

        .detail-layout {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .detail-nav {
            position: sticky;
            top: calc(var(--space-lg) * -1);
            z-index: 5;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            padding: 10px 0 12px;
            background: linear-gradient(to bottom, rgba(15, 15, 15, 0.98), rgba(15, 15, 15, 0.92));
            border-bottom: 1px solid var(--border-subtle);
            backdrop-filter: blur(8px);
        }

        .detail-nav button {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            letter-spacing: 0.08em;
            padding: 6px 10px;
            text-align: left;
            cursor: pointer;
            text-transform: uppercase;
        }

        .detail-nav button:hover,
        .detail-nav button.active {
            color: var(--accent);
            border-color: rgba(0, 255, 136, 0.35);
            background: rgba(0, 255, 136, 0.08);
        }

        .detail-main {
            min-width: 0;
        }

        .compare-diff {
            display: flex;
            flex-direction: column;
            gap: var(--space-lg);
        }

        .compare-toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            flex-wrap: wrap;
        }

        .compare-toolbar-group {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .compare-toggle {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 5px 9px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .compare-toggle.active {
            color: var(--accent);
            border-color: rgba(0, 255, 136, 0.35);
            background: rgba(0, 255, 136, 0.08);
        }

        .compare-status {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .compare-head {
            display: grid;
            grid-template-columns: 180px repeat(var(--compare-cols, 2), minmax(0, 1fr));
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
        }

        .compare-head-cell {
            background: var(--bg-panel);
            padding: 10px 12px;
            min-width: 0;
        }

        .compare-head-cell.center {
            text-align: center;
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        .compare-name {
            color: var(--accent);
            font-size: 13px;
            font-weight: 600;
            overflow-wrap: anywhere;
        }

        .compare-key {
            margin-top: 4px;
            color: var(--text-tertiary);
            font-size: 10px;
            overflow-wrap: anywhere;
        }

        .compare-section {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .compare-section-title {
            background: var(--bg-element);
            color: var(--text-dim);
            padding: 8px 10px;
            font-size: 10px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        .compare-row {
            display: grid;
            grid-template-columns: 180px repeat(var(--compare-cols, 2), minmax(0, 1fr));
            gap: 1px;
            background: var(--border-dim);
        }

        .compare-row.jumpable {
            cursor: pointer;
        }

        .compare-row.jumpable:hover .compare-cell,
        .compare-row.jumpable:hover .compare-label {
            background: rgba(0, 255, 136, 0.05);
        }

        .compare-row.unchanged {
            display: none;
        }

        .compare-diff.show-all .compare-row.unchanged {
            display: grid;
        }

        .compare-row + .compare-row {
            border-top: 1px solid var(--border-subtle);
        }

        .compare-cell,
        .compare-label {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .compare-label {
            text-align: center;
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .compare-cell {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            overflow-wrap: anywhere;
            white-space: pre-wrap;
        }

        .compare-cell.diff {
            box-shadow: inset 2px 0 0 rgba(255, 170, 0, 0.9);
            background: rgba(255, 170, 0, 0.07);
        }

        .compare-cell .diff-add {
            background: rgba(0, 255, 136, 0.16);
            color: var(--accent);
            padding: 0 1px;
        }

        .compare-cell .diff-del {
            background: rgba(255, 102, 0, 0.16);
            color: var(--state-warning);
            padding: 0 1px;
        }

        .compare-subsection {
            border-top: 1px solid var(--border-subtle);
            padding: 10px;
            background: var(--bg-panel);
        }

        .compare-subtitle {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }

        .detail-anchor {
            scroll-margin-top: 14px;
        }

        .frame-diagnostics {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: var(--space-md);
        }

        .comment-toolbar {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            margin-bottom: var(--space-md);
            align-items: center;
        }

        .comment-filters {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .comment-filter-btn {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 4px 8px;
            cursor: pointer;
            text-transform: uppercase;
        }

        .comment-filter-btn.active {
            color: var(--accent);
            border-color: rgba(0, 255, 136, 0.4);
        }

        .comment-search {
            min-width: min(320px, 100%);
            background: var(--bg-base);
            border: 1px solid var(--border-subtle);
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 11px;
            padding: 8px 10px;
        }

        .comment-search:focus {
            outline: none;
            border-color: var(--accent);
        }

        .comment-chunk.collapsed .comment-lane,
        .comment-chunk.collapsed .comment-scale,
        .comment-chunk.collapsed .comment-list {
            display: none;
        }

        .comment-chunk-head {
            cursor: pointer;
        }

        .detail-section {
            margin-bottom: var(--space-lg);
        }

        .detail-section:last-child {
            margin-bottom: 0;
        }

        .detail-label {
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
            text-transform: uppercase;
            margin-bottom: var(--space-sm);
        }

        .detail-value {
            font-size: 13px;
            color: var(--text-primary);
            overflow-wrap: anywhere;
            word-break: normal;
        }

        .detail-value.accent {
            color: var(--accent);
            font-weight: 600;
        }

        .detail-value.mono {
            font-family: var(--font-mono);
            font-size: 12px;
            background: var(--bg-base);
            padding: var(--space-sm) var(--space-md);
            border: 1px solid var(--border-dim);
            overflow-x: auto;
            white-space: pre-wrap;
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
            margin-bottom: var(--space-lg);
        }

        .detail-stat {
            background: var(--bg-panel);
            padding: var(--space-md);
            text-align: center;
        }

        .detail-stat .label {
            font-size: 9px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-dim);
            text-transform: uppercase;
            margin-bottom: var(--space-xs);
        }

        .detail-stat .value {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-secondary);
            font-variant-numeric: tabular-nums;
        }

        .detail-stat.nominal .value {
            color: var(--state-nominal);
        }

        .metadata-section {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            margin-top: var(--space-md);
        }

        .metadata-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-sm) var(--space-md);
            background: var(--bg-element);
            border-bottom: 1px solid var(--border-dim);
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.15em;
            color: var(--text-tertiary);
            text-transform: uppercase;
        }

        .metadata-header .badge {
            background: var(--accent);
            color: var(--bg-void);
            padding: 2px 8px;
            font-size: 9px;
            font-weight: 700;
        }

        .metadata-content {
            padding: var(--space-md);
            overflow: visible;
        }

        .metadata-list {
            display: flex;
            flex-direction: column;
            gap: var(--space-xs);
        }

        .metadata-item {
            display: flex;
            gap: var(--space-md);
            padding: var(--space-xs) var(--space-sm);
            font-size: 11px;
            border-left: 2px solid var(--border-dim);
            min-width: 0;
        }

        .metadata-item:hover {
            background: rgba(0, 255, 136, 0.05);
            border-left-color: var(--accent);
        }

        .metadata-item .name {
            color: var(--accent);
            font-weight: 600;
            min-width: 150px;
            overflow-wrap: anywhere;
            word-break: normal;
        }

        .metadata-item .info {
            color: var(--text-dim);
            overflow-wrap: anywhere;
        }

        .metadata-empty {
            color: var(--text-dim);
            font-size: 11px;
            font-style: italic;
        }

        .type-explorer {
            margin-top: var(--space-md);
            display: grid;
            gap: 14px;
        }

        .type-explorer-topbar {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            border: 1px solid rgba(80, 140, 220, 0.28);
            background: rgba(3, 10, 22, 0.7);
        }

        .type-explorer-stat {
            padding: 12px 14px;
            border-right: 1px solid rgba(80, 140, 220, 0.18);
            display: grid;
            gap: 8px;
            min-width: 0;
        }

        .type-explorer-stat:last-child {
            border-right: 0;
        }

        .type-explorer-stat .label {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.14em;
            text-transform: uppercase;
        }

        .type-explorer-stat .value {
            color: var(--text-secondary);
            font-size: 14px;
            line-height: 1.25;
            overflow-wrap: anywhere;
            font-weight: 600;
        }

        .type-explorer-stat .value.warn {
            color: #ff7b54;
        }

        .type-explorer-declaration {
            display: grid;
            gap: 8px;
        }

        .type-explorer-decl-box {
            border: 1px solid rgba(80, 140, 220, 0.22);
            background: rgba(5, 14, 28, 0.72);
            padding: 14px 18px;
            font-size: 15px;
            line-height: 1.5;
            overflow-wrap: anywhere;
        }

        .type-explorer-return {
            color: #4bb4ff;
        }

        .type-explorer-cc {
            color: var(--text-dim);
        }

        .type-explorer-func-name {
            color: #31f2b2;
            font-weight: 600;
            text-shadow: 0 0 10px rgba(49, 242, 178, 0.16);
        }

        .type-explorer-func-scope {
            color: var(--text-dim);
            font-weight: 500;
        }

        .type-explorer-arg-name {
            color: var(--text-dim);
            font-size: 12px;
        }

        .type-explorer-generic {
            color: var(--accent);
        }

        .type-explorer-togglebar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
        }

        .type-explorer-modes {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        .type-explorer-mode,
        .type-explorer-alloc-toggle {
            border: 1px solid transparent;
            background: transparent;
            color: var(--text-dim);
            padding: 10px 14px;
            font: inherit;
            letter-spacing: 0.14em;
            text-transform: uppercase;
            cursor: pointer;
        }

        .type-explorer-mode.active {
            border-color: rgba(64, 210, 170, 0.45);
            color: var(--accent);
            background: rgba(32, 160, 140, 0.12);
            box-shadow: inset 0 0 0 1px rgba(32, 160, 140, 0.12);
        }

        .type-explorer-alloc-toggle {
            border-color: rgba(255, 123, 84, 0.35);
            color: #ff7b54;
        }

        .type-explorer-canvas {
            border: 1px solid rgba(80, 140, 220, 0.22);
            background: rgba(2, 12, 24, 0.78);
            padding: 18px;
            min-height: 0;
        }

        .type-explorer-canvas.layered {
            padding: 20px 22px;
        }

        .type-explorer-canvas.horizontal {
            padding: 20px 16px 16px;
        }

        .type-explorer-layered {
            display: grid;
            gap: 8px;
        }

        .type-explorer-horizontal {
            display: grid;
            gap: 16px;
        }

        .type-horizontal-stage {
            overflow-x: auto;
            padding: 4px;
        }

        .type-horizontal-root {
            min-width: max-content;
        }

        .type-horizontal-node,
        .type-horizontal-leaf {
            display: inline-flex;
            flex-direction: column;
            border: 1px solid var(--layer-color, rgba(255,255,255,0.16));
            border-radius: 3px;
            background: color-mix(in srgb, var(--layer-color, rgba(255,255,255,0.16)) 7%, rgba(2, 12, 24, 0.94));
            min-width: 0;
        }

        .type-horizontal-head {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border-bottom: 1px solid color-mix(in srgb, var(--layer-color, rgba(255,255,255,0.14)) 30%, transparent);
            min-width: 0;
            cursor: pointer;
        }

        .type-horizontal-leaf {
            padding: 10px 14px;
        }

        .type-horizontal-children {
            display: flex;
            flex-wrap: nowrap;
            align-items: stretch;
            gap: 10px;
            padding: 12px 14px 14px;
            overflow-x: auto;
        }

        .type-horizontal-child {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            flex-shrink: 0;
        }

        .type-horizontal-sep {
            color: rgba(255,255,255,0.12);
            font-size: 18px;
            line-height: 1;
        }

        .type-horizontal-label {
            color: var(--layer-color, var(--accent));
            font-size: 14px;
            font-weight: 600;
            line-height: 1.1;
            overflow-wrap: anywhere;
        }

        .type-horizontal-meta {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .type-horizontal-note {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .type-horizontal-leaf .type-horizontal-label {
            font-size: 13px;
        }

        .type-layer-branch {
            position: relative;
            border-left: 2px solid var(--layer-color, rgba(255,255,255,0.14));
            padding-left: 16px;
            margin-left: 6px;
            display: grid;
            gap: 8px;
        }

        .type-layer-node {
            position: relative;
            display: grid;
            gap: 8px;
        }

        .type-layer-head {
            display: flex;
            align-items: center;
            gap: 8px;
            min-width: 0;
            flex-wrap: wrap;
        }

        .type-layer-pin {
            position: absolute;
            left: -24px;
            top: 8px;
            width: 14px;
            height: 14px;
            border-radius: 999px;
            border: 4px solid var(--layer-color, var(--accent));
            background: rgba(2, 12, 24, 0.9);
            box-sizing: border-box;
        }

        .type-layer-node.leaf .type-layer-pin {
            top: 50%;
            transform: translateY(-50%);
        }

        .type-layer-toggle {
            border: 0;
            background: transparent;
            color: var(--text-dim);
            padding: 0;
            width: 14px;
            text-align: center;
            cursor: pointer;
            font: inherit;
        }

        .type-layer-index,
        .type-layer-kicker {
            color: var(--text-dim);
            font-size: 9px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        .type-layer-label {
            color: var(--layer-color, var(--accent));
            font-size: 14px;
            line-height: 1.15;
            overflow-wrap: anywhere;
            font-weight: 600;
        }

        .type-layer-path {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.06em;
            overflow-wrap: anywhere;
        }

        .type-layer-meta {
            color: var(--text-dim);
            font-size: 12px;
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }

        .type-layer-chip {
            display: inline-flex;
            align-items: center;
            padding: 4px 8px;
            border: 1px solid rgba(255,255,255,0.18);
            color: var(--text-dim);
            background: rgba(255,255,255,0.02);
        }

        .type-layer-children {
            display: grid;
            gap: 10px;
            padding-left: 4px;
        }

        .type-compact-token {
            display: inline;
            font-size: 13px;
            font-family: var(--font-mono);
        }

        .type-compact-token.name {
            font-weight: 600;
        }

        .type-compact-token.punct {
            color: var(--text-dim);
            font-size: 11px;
        }

        .type-explorer-legend {
            display: flex;
            gap: 18px;
            flex-wrap: wrap;
            align-items: center;
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
        }

        .type-explorer-legend-item {
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .type-explorer-legend-dot {
            width: 16px;
            height: 16px;
            border-radius: 999px;
            background: var(--dot-color, var(--accent));
        }

        .type-explorer-raw {
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            cursor: pointer;
            user-select: none;
        }

        .type-explorer-raw-block {
            margin-top: 10px;
            border: 1px solid rgba(255,255,255,0.12);
            background: rgba(255,255,255,0.02);
            padding: 14px 16px;
            color: var(--text-dim);
            font-size: 12px;
            line-height: 1.6;
            overflow-wrap: anywhere;
        }
        .frame-viz {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .frame-map {
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            padding: var(--space-sm);
        }

        .frame-map-track {
            position: relative;
            height: 38px;
            border: 1px solid var(--border-dim);
            background:
                repeating-linear-gradient(
                    90deg,
                    rgba(255, 255, 255, 0.02) 0,
                    rgba(255, 255, 255, 0.02) 1px,
                    transparent 1px,
                    transparent 24px
                ),
                var(--bg-base);
            overflow: hidden;
        }

        .frame-segment {
            position: absolute;
            top: 4px;
            bottom: 4px;
            min-width: 2px;
            padding: 0 6px;
            border: 1px solid rgba(0, 255, 136, 0.5);
            background: rgba(0, 255, 136, 0.18);
            display: flex;
            align-items: center;
            overflow: hidden;
        }

        .frame-segment span {
            font-size: 10px;
            color: var(--accent);
            white-space: nowrap;
            text-overflow: ellipsis;
            overflow: hidden;
            max-width: 100%;
        }

        .frame-segment.frame-segment-self {
            border-color: rgba(255, 102, 0, 0.6);
            background: rgba(255, 102, 0, 0.18);
        }

        .frame-segment.frame-segment-self span {
            color: var(--state-warning);
        }

        .frame-map-scale {
            display: flex;
            justify-content: space-between;
            margin-top: var(--space-xs);
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-dim);
        }

        .frame-table-wrap {
            overflow-x: auto;
        }

        .frame-table {
            min-width: 680px;
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .frame-table-head,
        .frame-table-row {
            display: grid;
            grid-template-columns: minmax(160px, 1.1fr) 90px 90px minmax(280px, 2.4fr);
            gap: 1px;
            background: var(--border-dim);
        }

        .frame-table-head > div {
            background: var(--bg-element);
            padding: 8px 10px;
            font-size: 9px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--text-dim);
            font-weight: 700;
        }

        .frame-table-row > div {
            background: var(--bg-panel);
            padding: 8px 10px;
            font-size: 11px;
            min-width: 0;
        }

        .frame-table-row:nth-child(even) > div {
            background: rgba(255, 255, 255, 0.01);
        }

        .frame-member-slot {
            color: var(--text-dim);
            margin-right: var(--space-xs);
            font-family: var(--font-mono);
        }

        .frame-member-name {
            color: var(--accent);
            font-weight: 600;
            overflow-wrap: anywhere;
        }

        .frame-num {
            font-family: var(--font-mono);
            color: var(--text-secondary);
        }

        .frame-member-type {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
        }

        .frame-member-meta {
            margin-top: 6px;
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }

        .frame-chip {
            border: 1px solid var(--border-dim);
            padding: 1px 6px;
            font-size: 9px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--text-tertiary);
            background: var(--bg-base);
        }

        .frame-chip.warn {
            border-color: rgba(255, 102, 0, 0.6);
            color: var(--state-warning);
        }

        .frame-note {
            margin-top: 4px;
            font-size: 10px;
            color: var(--text-dim);
            overflow-wrap: anywhere;
        }

        .frame-note.warn {
            color: var(--state-warning);
        }

        .frame-missing {
            color: var(--text-dim);
            font-style: italic;
        }

        .signature-viz {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .signature-cards {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 1px;
            background: var(--border-dim);
            border: 1px solid var(--border-subtle);
        }

        .signature-card {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .signature-card .label {
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: var(--text-dim);
            margin-bottom: 4px;
        }

        .signature-card .value {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
        }

        .signature-card .value.accent {
            color: var(--accent);
        }

        .signature-args {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .signature-arg-row {
            display: grid;
            grid-template-columns: 90px 1fr;
            gap: 1px;
            background: var(--border-dim);
        }

        .signature-arg-row + .signature-arg-row {
            border-top: 1px solid var(--border-subtle);
        }

        .signature-arg-key,
        .signature-arg-val {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .signature-arg-key {
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--text-dim);
        }

        .signature-arg-val {
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
        }

        .comment-timeline {
            display: flex;
            flex-direction: column;
            gap: var(--space-md);
        }

        .comment-chunk {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: var(--space-sm);
            display: flex;
            flex-direction: column;
            gap: var(--space-sm);
        }

        .comment-chunk-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: var(--space-md);
            font-size: 10px;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--text-tertiary);
        }

        .comment-chunk-head .count {
            color: var(--text-dim);
            font-family: var(--font-mono);
            text-transform: none;
            letter-spacing: 0;
        }

        .comment-lane {
            position: relative;
            border: 1px solid var(--border-dim);
            background:
                linear-gradient(to bottom, rgba(255, 255, 255, 0.01), rgba(255, 255, 255, 0.01)),
                repeating-linear-gradient(
                    90deg,
                    rgba(255, 255, 255, 0.02) 0,
                    rgba(255, 255, 255, 0.02) 1px,
                    transparent 1px,
                    transparent 18px
                ),
                var(--bg-base);
            overflow: hidden;
        }

        .comment-marker {
            position: absolute;
            transform: translateX(-50%);
            width: 11px;
            height: 11px;
            border-radius: 50%;
            border: 1px solid rgba(0, 255, 136, 0.8);
            background: rgba(0, 255, 136, 0.3);
            box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.45);
            cursor: pointer;
            transition: transform 120ms ease, background 120ms ease;
            z-index: 2;
        }

        .comment-marker:hover {
            transform: translateX(-50%) scale(1.2);
            background: rgba(0, 255, 136, 0.45);
        }

        .comment-marker.active {
            transform: translateX(-50%) scale(1.3);
            background: rgba(0, 255, 136, 0.62);
            box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.45), 0 0 12px rgba(0, 255, 136, 0.55);
        }

        .comment-marker.repeatable {
            border-color: rgba(255, 102, 0, 0.8);
            background: rgba(255, 102, 0, 0.35);
        }

        .comment-marker.repeatable.active {
            background: rgba(255, 102, 0, 0.65);
            box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.45), 0 0 12px rgba(255, 102, 0, 0.55);
        }

        .comment-scale {
            display: flex;
            justify-content: space-between;
            font-family: var(--font-mono);
            font-size: 10px;
            color: var(--text-dim);
        }

        .comment-list {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
        }

        .comment-item {
            display: grid;
            grid-template-columns: 130px 1fr;
            gap: 1px;
            background: var(--border-dim);
            cursor: pointer;
        }

        .comment-item:hover .comment-item-head,
        .comment-item:hover .comment-item-text {
            background: rgba(0, 255, 136, 0.04);
        }

        .comment-item + .comment-item {
            border-top: 1px solid var(--border-subtle);
        }

        .comment-item.active .comment-item-head,
        .comment-item.active .comment-item-text {
            background: rgba(0, 255, 136, 0.08);
            box-shadow: inset 2px 0 0 rgba(0, 255, 136, 0.85);
        }

        .comment-item.active-controlflow .comment-item-head,
        .comment-item.active-controlflow .comment-item-text {
            background: rgba(255, 170, 0, 0.08);
            box-shadow: inset 2px 0 0 rgba(255, 170, 0, 0.9);
        }

        .comment-item.dimmed {
            opacity: 0.42;
        }

        .comment-item-head,
        .comment-item-text {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .comment-item-head {
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-secondary);
        }

        .comment-kind {
            border: 1px solid rgba(0, 255, 136, 0.5);
            color: var(--accent);
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            padding: 1px 4px;
            min-width: 32px;
            text-align: center;
            background: rgba(0, 255, 136, 0.12);
        }

        .comment-kind.repeatable {
            border-color: rgba(255, 102, 0, 0.5);
            color: var(--state-warning);
            background: rgba(255, 102, 0, 0.14);
        }

        .comment-item-text {
            font-size: 12px;
            color: var(--text-secondary);
            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }

        .controlflow-grid {
            display: grid;
            grid-template-columns: minmax(240px, 0.9fr) minmax(0, 1.6fr);
            gap: var(--space-md);
        }

        .controlflow-panel {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: var(--space-md);
            transition: opacity 140ms ease, transform 140ms ease, border-color 140ms ease;
        }

        .controlflow-panel.dimmed,
        .switch-group.dimmed,
        .jumptable-card.dimmed {
            opacity: 0.42;
        }

        .controlflow-toolbar {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            align-items: center;
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: 10px 12px;
            margin-bottom: var(--space-md);
        }

        .controlflow-toolbar-summary,
        .controlflow-toolbar-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            align-items: center;
        }

        .controlflow-active-filter {
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        .controlflow-focus-note {
            color: var(--text-dim);
            font-size: 11px;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }

        .controlflow-matrix {
            border: 1px solid var(--border-subtle);
            background: var(--border-dim);
            margin-bottom: var(--space-md);
        }

        .controlflow-matrix-row {
            display: grid;
            grid-template-columns: 150px minmax(0, 1fr);
            gap: 1px;
            background: var(--border-dim);
            cursor: pointer;
            transition: background 120ms ease;
        }

        .controlflow-matrix-row:hover .controlflow-matrix-cell,
        .controlflow-matrix-row.active .controlflow-matrix-cell {
            background: rgba(0, 255, 136, 0.05);
        }

        .controlflow-matrix-row + .controlflow-matrix-row {
            border-top: 1px solid var(--border-subtle);
        }

        .controlflow-matrix-cell {
            background: var(--bg-panel);
            padding: 8px 10px;
            min-width: 0;
        }

        .controlflow-matrix-label {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .controlflow-matrix-value {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            overflow-wrap: anywhere;
        }

        .controlflow-hero {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            padding: var(--space-md);
            margin-bottom: var(--space-md);
        }

        .controlflow-hero-title {
            color: var(--state-warning);
            font-size: 10px;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            margin-bottom: 6px;
        }

        .controlflow-hero-main {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            align-items: center;
        }

        .controlflow-hero-addr {
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 14px;
            overflow-wrap: anywhere;
        }

        .controlflow-hero-stats {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .controlflow-stack {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .switch-card {
            border: 1px solid var(--border-subtle);
            background: var(--bg-base);
            padding: 10px;
        }

        .switch-group {
            border: 1px solid var(--border-subtle);
            background: var(--bg-base);
        }

        .switch-group.collapsed .switch-group-body {
            display: none;
        }

        .switch-group-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 8px;
            padding: 10px;
            cursor: pointer;
            background: rgba(255,255,255,0.01);
            border-bottom: 1px solid var(--border-subtle);
        }

        .switch-group-body {
            padding: 8px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .switch-group-title {
            color: var(--accent);
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .switch-card:hover,
        .switch-card.active,
        .switch-card.linked {
            border-color: rgba(0, 255, 136, 0.28);
            background: rgba(0, 255, 136, 0.04);
        }

        .switch-card.active {
            border-color: rgba(255, 170, 0, 0.46);
            background: rgba(255, 170, 0, 0.06);
        }

        .switch-card-head {
            display: flex;
            justify-content: space-between;
            gap: 8px;
            align-items: center;
            margin-bottom: 6px;
        }

        .switch-title {
            color: var(--accent);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .switch-meta {
            color: var(--text-dim);
            font-family: var(--font-mono);
            font-size: 10px;
        }

        .switch-desc {
            color: var(--text-primary);
            font-family: var(--font-mono);
            font-size: 12px;
            overflow-wrap: anywhere;
        }

        .switch-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }

        .controlflow-group-strip {
            display: flex;
            flex-direction: column;
            gap: 6px;
            padding: 8px 10px;
            border-top: 1px solid var(--border-subtle);
            background: rgba(255, 255, 255, 0.015);
        }

        .controlflow-group-strip-head {
            display: flex;
            justify-content: space-between;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .controlflow-group-strip-label {
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .controlflow-density-strip {
            display: grid;
            grid-template-columns: repeat(18, minmax(0, 1fr));
            gap: 3px;
        }

        .controlflow-density-bin {
            height: 10px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
        }

        button.controlflow-density-bin {
            padding: 0;
            cursor: pointer;
        }

        .controlflow-density-bin.fill {
            background: rgba(0, 255, 136, 0.32);
            border-color: rgba(0, 255, 136, 0.18);
        }

        .controlflow-density-bin.default {
            background: rgba(255, 170, 0, 0.42);
            border-color: rgba(255, 170, 0, 0.24);
        }

        .controlflow-density-bin.active {
            box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.35), 0 0 0 1px rgba(255, 170, 0, 0.35);
        }

        .controlflow-density-bin:hover {
            transform: translateY(-1px);
        }

        .controlflow-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: var(--space-md);
        }

        .jumptable-card {
            border: 1px solid var(--border-subtle);
            background: var(--bg-panel);
            overflow: hidden;
        }

        .jumptable-head {
            display: flex;
            justify-content: space-between;
            gap: var(--space-md);
            flex-wrap: wrap;
            padding: 10px 12px;
            background: var(--bg-element);
            border-bottom: 1px solid var(--border-subtle);
        }

        .jumptable-title {
            color: var(--accent);
            font-family: var(--font-mono);
            font-size: 12px;
            overflow-wrap: anywhere;
        }

        .jumptable-badges {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }

        .jumptable-cluster-note {
            margin-top: 6px;
            color: var(--text-dim);
            font-size: 10px;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }

        .jumptable-coverage {
            border-top: 1px solid var(--border-subtle);
            padding: 10px 12px 8px;
            background: rgba(255,255,255,0.01);
        }

        .jumptable-coverage-strip {
            display: grid;
            grid-template-columns: repeat(24, minmax(0, 1fr));
            gap: 3px;
            margin-top: 8px;
        }

        .coverage-bin {
            height: 14px;
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            position: relative;
            overflow: hidden;
        }

        .coverage-bin.fill::before {
            content: "";
            position: absolute;
            inset: 0;
            background: rgba(0,255,136,0.45);
        }

        .coverage-bin.default::before {
            background: rgba(255,170,0,0.55);
        }

        .coverage-bin.active {
            box-shadow: 0 0 0 1px rgba(255, 170, 0, 0.4);
        }

        .coverage-meta {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        .jumptable-more {
            margin-top: 8px;
        }

        .controlflow-toggle {
            background: var(--bg-base);
            border: 1px solid var(--border-dim);
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 10px;
            padding: 4px 8px;
            cursor: pointer;
        }

        .controlflow-toggle:hover {
            border-color: rgba(0, 255, 136, 0.28);
            color: var(--text-primary);
        }

        .jumptable-ref-list {
            display: flex;
            flex-direction: column;
        }

        .jumptable-ref {
            display: grid;
            grid-template-columns: 96px minmax(0, 1fr);
            gap: 1px;
            background: var(--border-dim);
        }

        .jumptable-ref + .jumptable-ref {
            border-top: 1px solid var(--border-subtle);
        }

        .jumptable-ref.active .jumptable-ref-meta,
        .jumptable-ref.active .jumptable-ref-body {
            background: rgba(255, 170, 0, 0.06);
            box-shadow: inset 2px 0 0 rgba(255, 170, 0, 0.92);
        }

        .jumptable-ref-meta,
        .jumptable-ref-body {
            background: var(--bg-panel);
            padding: 6px 8px;
            min-width: 0;
        }

        .jumptable-ref-meta {
            color: var(--text-dim);
            font-family: var(--font-mono);
            font-size: 9px;
            line-height: 1.35;
        }

        .jumptable-ref-body {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 11px;
            overflow-wrap: anywhere;
        }

        .jumptable-case-strip {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }

        .case-chip {
            border: 1px solid rgba(0, 255, 136, 0.28);
            background: rgba(0, 255, 136, 0.08);
            color: var(--accent);
            padding: 2px 6px;
            font-size: 10px;
            font-family: var(--font-mono);
        }

        button.case-chip {
            cursor: pointer;
        }

        .case-chip.default {
            border-color: rgba(255, 170, 0, 0.4);
            background: rgba(255, 170, 0, 0.1);
            color: var(--state-warning);
        }

        .case-chip.active {
            border-color: rgba(255, 170, 0, 0.55);
            background: rgba(255, 170, 0, 0.16);
            color: var(--text-primary);
        }

        .jumptable-graph {
            border: 1px solid var(--border-subtle);
            background: var(--bg-base);
            padding: 10px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .jumptable-ref.linked,
        .comment-item.linked {
            box-shadow: inset 2px 0 0 rgba(0, 255, 136, 0.7);
            background: rgba(0, 255, 136, 0.04);
        }

        .controlflow-actions {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        .switch-links {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 8px;
        }

        .relation-summary {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            align-items: center;
            margin-bottom: 4px;
        }

        .relation-detail {
            color: var(--text-dim);
            font-size: 10px;
            line-height: 1.3;
        }

        .comment-item-text.controlflow {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .comment-flow-main {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            align-items: center;
        }

        .comment-flow-detail {
            color: var(--text-dim);
            font-size: 11px;
            line-height: 1.35;
        }

        .jumptable-graph-node {
            border: 1px solid var(--border-dim);
            background: var(--bg-base);
            padding: 8px 10px;
        }

        .jumptable-graph-node.active {
            border-color: rgba(255, 170, 0, 0.4);
            background: rgba(255, 170, 0, 0.05);
        }

        .jumptable-graph-node.root {
            border-color: rgba(0, 255, 136, 0.35);
        }

        .jumptable-graph-label {
            color: var(--text-dim);
            font-size: 9px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 4px;
        }

        .jumptable-graph-value {
            color: var(--text-secondary);
            font-family: var(--font-mono);
            font-size: 12px;
            overflow-wrap: anywhere;
        }

        .jumptable-graph-badges {
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-top: 6px;
        }

        .jumptable-graph-edge {
            border-left: 1px solid rgba(0, 255, 136, 0.3);
            margin-left: 12px;
            padding-left: 14px;
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .detail-loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: var(--space-2xl);
            color: var(--text-dim);
        }

        .result-item.clickable {
            cursor: pointer;
        }

        .result-item.clickable:hover {
            background: var(--bg-elevated);
            border-left: 3px solid var(--accent);
        }

        /* ─────────────────────────────────────────────────────────────
           EMPTY / LOADING STATES
           ───────────────────────────────────────────────────────────── */
        
        .state-message {
            text-align: center;
            padding: var(--space-2xl);
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
        }
        
        .state-message .icon {
            font-size: 32px;
            color: var(--text-dim);
            margin-bottom: var(--space-md);
        }
        
        .state-message h3 {
            font-family: var(--font-display);
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 0.1em;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin: 0 0 var(--space-sm) 0;
        }
        
        .state-message p {
            font-size: 12px;
            color: var(--text-dim);
            margin: 0;
        }
        
        /* ─────────────────────────────────────────────────────────────
           FOOTER - SYSTEM TELEMETRY BAR
           ───────────────────────────────────────────────────────────── */
        
        .telemetry-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: var(--space-md);
            background: var(--bg-panel);
            border: 1px solid var(--border-subtle);
            margin-top: var(--space-xl);
            font-size: 10px;
            color: var(--text-dim);
            letter-spacing: 0.1em;
        }
        
        .telemetry-left,
        .telemetry-right {
            display: flex;
            gap: var(--space-lg);
        }
        
        .telemetry-item {
            display: flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .telemetry-item .dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--text-dim);
        }
        
        .telemetry-item .dot.active { background: var(--state-nominal); }
        .telemetry-item .dot.warn { background: var(--state-warning); }
        .telemetry-item .dot.error { background: var(--state-critical); }
        
        .telemetry-center {
            color: var(--text-tertiary);
            display: flex;
            flex-direction: column;
            gap: 4px;
            align-items: center;
        }

        .telemetry-rates {
            font-size: 9px;
            color: var(--text-dim);
            letter-spacing: 0.08em;
            white-space: nowrap;
        }

        .proto-mix {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            margin-left: 8px;
            font-size: 9px;
            color: var(--text-dim);
        }

        .proto-donut {
            width: 18px;
            height: 18px;
            border-radius: 50%;
            background: conic-gradient(var(--accent) 0deg, var(--accent) 180deg, rgba(255, 102, 0, 0.8) 180deg, rgba(255, 102, 0, 0.8) 360deg);
            border: 1px solid var(--border-subtle);
            position: relative;
        }

        .proto-donut::after {
            content: "";
            position: absolute;
            inset: 4px;
            border-radius: 50%;
            background: var(--bg-panel);
        }
        
        /* ─────────────────────────────────────────────────────────────
           DECORATIVE ELEMENTS
           ───────────────────────────────────────────────────────────── */
        
        .bracket-wrap {
            display: inline-flex;
            align-items: center;
            gap: var(--space-xs);
        }
        
        .bracket-wrap::before { content: "["; color: var(--text-dim); }
        .bracket-wrap::after { content: "]"; color: var(--text-dim); }
        
        .direction-indicator {
            color: var(--text-dim);
            letter-spacing: -2px;
        }
        
        .divider-line {
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--border-subtle), transparent);
            margin: var(--space-lg) 0;
        }
        
        .dot-sequence {
            display: flex;
            gap: 4px;
        }
        
        .dot-sequence .dot {
            width: 4px;
            height: 4px;
            border-radius: 50%;
            background: var(--border-subtle);
        }
        
        .dot-sequence .dot.active {
            background: var(--accent);
        }
        
        /* ─────────────────────────────────────────────────────────────
           RESPONSIVE ADJUSTMENTS
           ───────────────────────────────────────────────────────────── */
        
        @media (max-width: 1200px) {
            .classification-bar,
            .search-row,
            .search-meta,
            .compare-panel-actions,
            .compare-toolbar-row,
            .compare-search-row,
            .binary-compare-grid,
            .compare-list-grid,
            .detail-grid,
            .related-binary-row,
            .timeline-row {
                grid-template-columns: 1fr;
            }

            .classification-bar,
            .search-row,
            .search-meta,
            .compare-panel-actions,
            .compare-toolbar,
            .compare-toolbar-row,
            .compare-search-row,
            .binary-compare-grid,
            .compare-list-grid {
                flex-wrap: wrap;
            }

            .related-binary-row,
            .timeline-row {
                gap: var(--space-lg);
            }

            .timeline-metric-row,
            .related-overlap-row {
                grid-template-columns: 1fr;
                gap: 6px;
            }

            .timeline-metric-label,
            .related-overlap-label,
            .timeline-meta {
                text-align: left;
                justify-items: start;
            }

            .dashboard-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .metric-wide {
                grid-column: span 1;
            }
            .metrics-secondary {
                grid-template-columns: repeat(2, 1fr);
            }

            .result-preview-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }
        
        @media (max-width: 768px) {
            .classification-bar,
            .brand-block,
            .search-row,
            .search-mode-switch,
            .search-input-wrap,
            .compare-panel-head,
            .compare-panel-actions,
            .compare-toolbar,
            .compare-toolbar-row,
            .compare-mode-switch,
            .results-title,
            .results-meta,
            .results-tools,
            .binary-overlap-actions,
            .binary-name-row {
                flex-direction: column;
                align-items: stretch;
            }

            .classification-bar {
                gap: 10px;
                align-items: flex-start;
            }

            .classification-bar .doc-code,
            .results-title,
            .results-meta,
            .modal-title,
            .detail-value,
            .coverage-card .value,
            .compare-item-name,
            .compare-name {
                overflow-wrap: anywhere;
            }

            .search-row {
                gap: var(--space-md);
            }

            .search-prompt,
            .search-kbd {
                display: none;
            }

            .search-mode-switch,
            .search-input-wrap,
            .search-input,
            .compare-field,
            .comment-search,
            .sort-controls,
            .sort-controls select {
                width: 100%;
            }

            .search-mode-btn,
            .pagination-btn,
            .result-action {
                width: 100%;
                justify-content: center;
            }

            .detail-page-shell {
                margin-top: var(--space-md);
            }

            .page-panel {
                box-shadow: none;
            }

            .modal-header,
            .modal-body {
                padding: var(--space-md);
            }

            .detail-nav {
                top: 0;
                margin: 0 calc(var(--space-md) * -1);
                padding-left: var(--space-md);
                padding-right: var(--space-md);
                overflow-x: auto;
                flex-wrap: nowrap;
            }

            .detail-nav button {
                flex: 0 0 auto;
            }

            .compare-list-grid,
            .binary-compare-grid,
            .signature-cards,
            .result-preview-grid {
                grid-template-columns: 1fr;
            }

            .compare-item-row,
            .result-key,
            .result-meta,
            .neighbor-card-header,
            .metadata-header,
            .telemetry-left,
            .telemetry-center,
            .telemetry-right {
                flex-direction: column;
                align-items: flex-start;
            }

            .result-bins,
            .compare-panel-list,
            .compare-list-column,
            .metadata-content {
                min-width: 0;
            }

            .neighbor-card-actions {
                justify-items: start;
                width: 100%;
            }

            .neighbor-pill-row {
                justify-content: flex-start;
            }

            .header-grid {
                grid-template-columns: 1fr;
                gap: var(--space-lg);
                text-align: center;
            }
            .header-left, .header-right {
                align-items: center;
                text-align: center;
            }
            .dashboard-grid,
            .metrics-secondary {
                grid-template-columns: 1fr;
            }
            .metric-wide {
                grid-column: span 1;
            }
            .telemetry-bar {
                flex-direction: column;
                gap: var(--space-md);
            }

            .results-header {
                flex-direction: column;
            }

            .results-tools {
                align-items: flex-start;
                width: 100%;
            }

            .compare-panel {
                align-items: flex-start;
            }

            .results-hint {
                display: block;
                width: 100%;
            }

            .telemetry-rates {
                white-space: normal;
                text-align: center;
            }

            .proto-mix {
                margin-left: 0;
            }
            .terminal-frame {
                padding: var(--space-md);
            }

            .modal-header {
                padding: var(--space-md);
            }

            .modal-title {
                font-size: 10px;
                letter-spacing: 0.12em;
            }

            .modal-body {
                padding: var(--space-md);
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }

            .detail-nav {
                position: static;
            }

            .metadata-header {
                align-items: flex-start;
                flex-direction: column;
                gap: var(--space-sm);
            }

            .metadata-item,
            .metadata-item > div:first-child {
                flex-direction: column;
                align-items: flex-start !important;
            }

            .metadata-item .name {
                min-width: 0;
            }

            .frame-map-track {
                height: 34px;
            }

            .frame-table {
                min-width: 560px;
            }

            .signature-cards {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .comment-item {
                grid-template-columns: 1fr;
            }

            .controlflow-grid,
            .jumptable-ref {
                grid-template-columns: 1fr;
            }

            .controlflow-matrix-row {
                grid-template-columns: 1fr;
            }

            .workbench-layout {
                grid-template-columns: 1fr;
            }

            .workbench-side {
                position: static;
            }

            .binary-graph-toolbar {
                grid-template-columns: 1fr;
            }

            .binary-graph-controls {
                margin-left: 0;
            }
        }

        @media (max-width: 480px) {
            .terminal-frame {
                padding: 12px;
            }

            .classification-bar,
            .search-terminal,
            .results-header,
            .page-panel,
            .metric-card,
            .metric-mini,
            .compare-panel,
            .metadata-section,
            .result-item,
            .timeline-row,
            .related-binary-row,
            .compare-list-column,
            .coverage-card {
                padding-left: 12px;
                padding-right: 12px;
            }

            .brand-name {
                font-size: clamp(36px, 14vw, 64px);
            }

            .brand-sub,
            .serial-block,
            .coord-block,
            .telemetry-bar,
            .results-title,
            .modal-title {
                letter-spacing: 0.12em;
            }

            .binary-short-id {
                width: 100%;
                justify-content: center;
            }

            .compare-item-row,
            .metadata-item,
            .result-main,
            .result-meta {
                gap: var(--space-sm);
            }

            .frame-table,
            .compare-diff-table,
            .detail-table-wrap {
                min-width: 100%;
                overflow-x: auto;
                display: block;
            }

            .result-item {
                grid-template-columns: 1fr;
                gap: var(--space-md);
            }
            .result-index {
                width: fit-content;
            }
            .result-meta {
                flex-direction: row;
                align-items: center;
                justify-content: space-between;
                flex-wrap: wrap;
            }

            .result-actions {
                justify-content: flex-start;
            }

            .result-preview-grid {
                grid-template-columns: 1fr;
            }

            .compare-head,
            .compare-row {
                grid-template-columns: 1fr;
            }

            .modal-close {
                width: 36px;
                height: 36px;
                flex: 0 0 36px;
            }

            .signature-cards {
                grid-template-columns: 1fr;
            }

            .signature-arg-row {
                grid-template-columns: 1fr;
            }

            .type-explorer-topbar {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .type-explorer-canvas {
                padding: 14px;
            }

            .type-horizontal-children {
                flex-direction: column;
                align-items: stretch;
            }

            .type-horizontal-child {
                width: 100%;
            }

            .type-horizontal-sep {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="terminal-frame">
        <!-- Classification Banner -->
        <div class="classification-bar">
            <span>DAZHBOG FUNCTION INDEX TERMINAL</span>
            <span class="doc-code">DOC: DZB-SYS-001-R4 // OPERATIONAL</span>
        </div>
        
        <!-- Main Header Grid -->
        <header class="header-grid">
            <div class="header-left">
                <div class="brand-block">
                    <div class="brand-icon">
                        <div class="ring ring-outer"></div>
                        <div class="ring ring-inner"></div>
                        <div class="core"></div>
                    </div>
                    <div class="brand-text">
                        <div class="brand-name">DAZHBOG</div>
                        <div class="brand-sub">Function Metadata Server</div>
                    </div>
                </div>
                <div class="serial-block">
                    <span><span class="label">NODE ID</span><span id="node-id">DZB-001-ALPHA</span></span>
                    <span><span class="label">VERSION</span><span id="sys-version">v1.0.0</span></span>
                    <span><span class="label">PROTOCOL</span><span>LUMINA/TCP</span></span>
                </div>
            </div>
            
            <div class="header-center">
                <div class="status-ring" id="status-ring">
                    <div class="status-core"></div>
                </div>
                <div class="status-label" id="status-label">OPERATIONAL</div>
            </div>
            
            <div class="header-right">
                <div class="timestamp-block" id="timestamp">00:00:00</div>
                <div class="uptime-block">UPTIME <span id="uptime">0d 0h 0m</span></div>
                <div class="coord-block">
                    <span>LAT 00.0000 // LON 00.0000</span>
                    <span>SECTOR: PRIMARY</span>
                </div>
            </div>
        </header>
        
        <!-- Search Terminal -->
        <section class="search-terminal">
            <div class="search-row">
                <div class="search-mode-switch" id="search-mode-switch">
                    <button class="search-mode-btn active" id="mode-functions" onclick="setSearchMode('functions')">Functions</button>
                    <button class="search-mode-btn" id="mode-binaries" onclick="setSearchMode('binaries')">Binaries</button>
                </div>
                <span class="search-prompt">&gt;&gt;&gt;</span>
                <div class="search-input-wrap">
                    <input type="text" id="q" class="search-input" placeholder="ENTER FUNCTION QUERY: name, demangled symbol, or binary..." autocomplete="off" spellcheck="false">
                    <span class="search-kbd">LIVE</span>
                </div>
            </div>
            <div class="search-meta">
                <span>ENTITY: <span class="accent" id="search-entity-label">FUNCTIONS</span></span>
                <span>INDEX: <span class="accent" id="index-status">READY</span></span>
                <span>PER PAGE: <span class="accent">25</span></span>
                <span>PRESS <span class="accent">/</span> TO FOCUS</span>
            </div>
        </section>

        <section class="compare-panel compact hidden" id="compare-panel">
            <div class="compare-panel-head">
                <span class="compare-title">Compare Panel</span>
                <span class="compare-panel-summary" id="compare-summary">No functions queued</span>
            </div>
            <div class="compare-panel-actions">
                <button class="pagination-btn" id="compare-open" disabled>Open Compare</button>
                <button class="pagination-btn" id="compare-clear">Clear</button>
                <button class="pagination-btn" id="compare-save">Save Set</button>
                <button class="pagination-btn" id="compare-export">Export JSON</button>
                <button class="pagination-btn" id="compare-import">Import JSON</button>
                <select id="compare-load"><option value="">Load Set</option></select>
            </div>
            <div class="compare-panel-list" id="compare-list"></div>
        </section>
        
        <!-- Main Content -->
        <main>
            <!-- Primary Metrics Dashboard -->
            <div id="dashboard" class="dashboard-grid">
                <div class="metric-section-header">
                    <span>DATABASE STATUS</span>
                    <span class="section-code">SEC-000</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">Indexed Functions</span>
                        <span class="metric-code">IDX</span>
                    </div>
                    <div class="metric-value" id="m-indexed">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Unique Keys</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Storage Used</span>
                        <span class="metric-code">STO</span>
                    </div>
                    <div class="metric-value" id="m-storage">0 B</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Segment Data</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Search Docs</span>
                        <span class="metric-code">DOC</span>
                    </div>
                    <div class="metric-value" id="m-searchdocs">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Searchable</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Unique Binaries</span>
                        <span class="metric-code">BIN</span>
                    </div>
                    <div class="metric-value" id="m-binaries">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Observed</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-section-header">
                    <span>TRAFFIC ANALYSIS</span>
                    <span class="section-code">SEC-001</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">Queries Processed</span>
                        <span class="metric-code">QRY</span>
                    </div>
                    <div class="metric-value" id="m-queried">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Total Lookups</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Active RPC</span>
                        <span class="metric-code">RPC</span>
                    </div>
                    <div class="metric-value" id="m-rpc">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Live Connections</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Upstream Relay</span>
                        <span class="metric-code">UPS</span>
                    </div>
                    <div class="metric-value" id="m-upstream">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Lumina Requests</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Upstream Fetched</span>
                        <span class="metric-code">FTC</span>
                    </div>
                    <div class="metric-value" id="m-fetched">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">From Origin</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-section-header">
                    <span>INDEX OPERATIONS</span>
                    <span class="section-code">SEC-002</span>
                </div>
                
                <div class="metric-card nominal">
                    <div class="metric-header">
                        <span class="metric-label">New Functions</span>
                        <span class="metric-code">NEW</span>
                    </div>
                    <div class="metric-value" id="m-new">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Unique Indexed</span>
                        <div class="metric-indicator">
                            <div class="bar active"></div>
                            <div class="bar active"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Pull Operations</span>
                        <span class="metric-code">PUL</span>
                    </div>
                    <div class="metric-value" id="m-pulls">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Metadata Syncs</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Push Operations</span>
                        <span class="metric-code">PSH</span>
                    </div>
                    <div class="metric-value" id="m-pushes">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Submissions</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
                
                <div class="metric-card">
                    <div class="metric-header">
                        <span class="metric-label">Scoring Batches</span>
                        <span class="metric-code">SCR</span>
                    </div>
                    <div class="metric-value" id="m-scoring">0</div>
                    <div class="metric-footer">
                        <span class="metric-sub">Version Selection</span>
                        <div class="metric-indicator">
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                            <div class="bar"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Secondary Metrics Row -->
            <div id="metrics-secondary" class="metrics-secondary">
                <div class="metric-mini error">
                    <div class="label">Errors</div>
                    <div class="value" id="m-errors">0</div>
                    <div class="sparkline" id="spark-errors"></div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Timeouts</div>
                    <div class="value" id="m-timeouts">0</div>
                    <div class="sparkline" id="spark-timeouts"></div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Decode Rejects</div>
                    <div class="value" id="m-rejects">0</div>
                    <div class="sparkline" id="spark-rejects"></div>
                </div>
                <div class="metric-mini error">
                    <div class="label">Storage Fails</div>
                    <div class="value" id="m-append">0</div>
                    <div class="sparkline" id="spark-append"></div>
                </div>
                <div class="metric-mini warn">
                    <div class="label">Index Overflow</div>
                    <div class="value" id="m-overflow">0</div>
                    <div class="sparkline" id="spark-overflow"></div>
                </div>
                <div class="metric-mini error">
                    <div class="label">Upstream Errors</div>
                    <div class="value" id="m-uperr">0</div>
                    <div class="sparkline" id="spark-uperr"></div>
                </div>
                <div class="metric-mini">
                    <div class="label">Total Records</div>
                    <div class="value" id="m-totalrec">0</div>
                    <div class="metric-rate" id="rate-totalrec"></div>
                </div>
                <div class="metric-mini">
                    <div class="label">Versions Scored</div>
                    <div class="value" id="m-vconsidered">0</div>
                    <div class="metric-rate" id="rate-vconsidered"></div>
                </div>
                <div class="metric-mini">
                    <div class="label">Fallback Picks</div>
                    <div class="value" id="m-fallback">0</div>
                    <div class="metric-rate" id="rate-fallback"></div>
                </div>
            </div>
            
            <!-- Search Results Container -->
            <div id="results" class="results-container">
                <div class="results-header">
                    <div class="results-header-main">
                        <div class="results-title">
                            <span>QUERY RESULTS</span>
                            <span class="results-count" id="results-count">0</span>
                            <span class="results-total" id="results-total-label"></span>
                            <span class="results-intent" id="results-intent">INTENT: -</span>
                            <span class="results-hint" id="results-hint"></span>
                        </div>
                        <div class="results-meta">
                            <span>LATENCY: <span id="results-latency">0ms</span></span>
                            <span>QUERY: "<span id="results-query"></span>"</span>
                        </div>
                    </div>
                    <div class="results-tools">
                        <div class="sort-controls">
                            <label for="results-sort">Sort</label>
                            <select id="results-sort">
                                <option value="score">Score (Default)</option>
                                <option value="name">Name A-Z</option>
                                <option value="binaries">Binaries Count</option>
                                <option value="lang">Language</option>
                                <option value="recent">Most Recent</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="results-list" id="results-list"></div>
                <div class="pagination" id="pagination"></div>
            </div>

            <section id="detail-page" class="results-container detail-page-shell">
                <div class="page-panel">
                    <div class="modal-header">
                        <span class="modal-title" id="modal-title">FUNCTION DETAIL // <span id="modal-key"></span></span>
                        <button class="modal-close" onclick="closeDetailModal()">&times;</button>
                    </div>
                    <div class="modal-body" id="modal-body">
                        <div class="detail-loading">&gt;&gt;&gt; LOADING...</div>
                    </div>
                </div>
            </section>

            <section id="binary-compare-page" class="results-container detail-page-shell">
                <div class="page-panel compare-panel-page">
                    <div class="modal-header">
                        <span class="modal-title">BINARY COMPARE // <span id="binary-compare-title">-</span></span>
                        <button class="modal-close" onclick="closeBinaryCompareModal()">&times;</button>
                    </div>
                    <div class="modal-body" id="binary-compare-body">
                        <div class="detail-loading">&gt;&gt;&gt; LOADING COMPARE...</div>
                    </div>
                </div>
            </section>
        </main>

        <input type="file" id="compare-import-file" accept="application/json,.json" style="display:none;">

        <!-- Telemetry Footer -->
        <footer class="telemetry-bar">
            <div class="telemetry-left">
                <div class="telemetry-item">
                    <span class="dot active" id="tel-storage"></span>
                    <span>STORAGE</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot active" id="tel-index"></span>
                    <span>INDEX</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot active" id="tel-network"></span>
                    <span>NETWORK</span>
                </div>
                <div class="telemetry-item">
                    <span class="dot" id="tel-upstream"></span>
                    <span>UPSTREAM</span>
                </div>
            </div>
            <div class="telemetry-center">
                <span id="sys-time"></span>
                <span class="telemetry-rates">QPS <span id="rate-qps">+0.00/s</span> | PULL <span id="rate-pulls">+0.00/s</span> | PUSH <span id="rate-pushes">+0.00/s</span></span>
            </div>
            <div class="telemetry-right">
                <span>PROTOCOL V5+ CLIENTS: <span id="proto-v5">0</span></span>
                <span>LEGACY CLIENTS: <span id="proto-v0">0</span></span>
                <div class="proto-mix">
                    <div class="proto-donut" id="proto-mix-donut"></div>
                    <span id="proto-mix-label">V5 0% / LEG 0%</span>
                </div>
            </div>
        </footer>
    </div>
    
    <script>
        /* ═══════════════════════════════════════════════════════════════
           DAZHBOG TERMINAL INTERFACE - AXIOM CONTROL SYSTEM
           Document: DZB-JS-001 // Classification: OPERATIONAL
           ═══════════════════════════════════════════════════════════════ */

        const el = {
            q: document.getElementById('q'),
            searchEntityLabel: document.getElementById('search-entity-label'),
            modeFunctions: document.getElementById('mode-functions'),
            modeBinaries: document.getElementById('mode-binaries'),
            indexStatus: document.getElementById('index-status'),
            dashboard: document.getElementById('dashboard'),
            secondary: document.getElementById('metrics-secondary'),
            results: document.getElementById('results'),
            resultsList: document.getElementById('results-list'),
            resultsCount: document.getElementById('results-count'),
            resultsTotalLabel: document.getElementById('results-total-label'),
            resultsLatency: document.getElementById('results-latency'),
            resultsQuery: document.getElementById('results-query'),
            resultsIntent: document.getElementById('results-intent'),
            resultsHint: document.getElementById('results-hint'),
            resultsSort: document.getElementById('results-sort'),
            comparePanel: document.getElementById('compare-panel'),
            compareSummary: document.getElementById('compare-summary'),
            compareList: document.getElementById('compare-list'),
            compareOpen: document.getElementById('compare-open'),
            compareClear: document.getElementById('compare-clear'),
            compareSave: document.getElementById('compare-save'),
            compareExport: document.getElementById('compare-export'),
            compareImport: document.getElementById('compare-import'),
            compareLoad: document.getElementById('compare-load'),
            compareImportFile: document.getElementById('compare-import-file'),
            pagination: document.getElementById('pagination'),
            statusRing: document.getElementById('status-ring'),
            statusLabel: document.getElementById('status-label'),
            timestamp: document.getElementById('timestamp'),
            uptime: document.getElementById('uptime'),
            sysTime: document.getElementById('sys-time'),
            mIndexed: document.getElementById('m-indexed'),
            mStorage: document.getElementById('m-storage'),
            mSearchDocs: document.getElementById('m-searchdocs'),
            mBinaries: document.getElementById('m-binaries'),
            mQueried: document.getElementById('m-queried'),
            mRpc: document.getElementById('m-rpc'),
            mUpstream: document.getElementById('m-upstream'),
            mFetched: document.getElementById('m-fetched'),
            mNew: document.getElementById('m-new'),
            mPulls: document.getElementById('m-pulls'),
            mPushes: document.getElementById('m-pushes'),
            mScoring: document.getElementById('m-scoring'),
            mErrors: document.getElementById('m-errors'),
            mTimeouts: document.getElementById('m-timeouts'),
            mRejects: document.getElementById('m-rejects'),
            mAppend: document.getElementById('m-append'),
            mOverflow: document.getElementById('m-overflow'),
            mUpErr: document.getElementById('m-uperr'),
            mTotalRec: document.getElementById('m-totalrec'),
            mVconsidered: document.getElementById('m-vconsidered'),
            mFallback: document.getElementById('m-fallback'),
            rateTotalRec: document.getElementById('rate-totalrec'),
            rateVconsidered: document.getElementById('rate-vconsidered'),
            rateFallback: document.getElementById('rate-fallback'),
            sparkErrors: document.getElementById('spark-errors'),
            sparkTimeouts: document.getElementById('spark-timeouts'),
            sparkRejects: document.getElementById('spark-rejects'),
            sparkAppend: document.getElementById('spark-append'),
            sparkOverflow: document.getElementById('spark-overflow'),
            sparkUpErr: document.getElementById('spark-uperr'),
            telStorage: document.getElementById('tel-storage'),
            telIndex: document.getElementById('tel-index'),
            telNetwork: document.getElementById('tel-network'),
            telUpstream: document.getElementById('tel-upstream'),
            protoV5: document.getElementById('proto-v5'),
            protoV0: document.getElementById('proto-v0'),
            rateQps: document.getElementById('rate-qps'),
            ratePulls: document.getElementById('rate-pulls'),
            ratePushes: document.getElementById('rate-pushes'),
            protoMixDonut: document.getElementById('proto-mix-donut'),
            protoMixLabel: document.getElementById('proto-mix-label'),
            detailPage: document.getElementById('detail-page'),
            binaryComparePage: document.getElementById('binary-compare-page'),
            binaryCompareTitle: document.getElementById('binary-compare-title'),
            binaryCompareBody: document.getElementById('binary-compare-body'),
            modalTitle: document.getElementById('modal-title'),
            modalKey: document.getElementById('modal-key'),
            modalBody: document.getElementById('modal-body'),
        };

        let searchDebounceTimer = null;
        const DEBOUNCE_MS = 300;
        let currentPage = 1;
        let currentQuery = '';
        let currentSearchMode = 'functions';
        let currentHits = [];
        let currentTotalPages = 0;
        let currentPerPage = 25;
        let currentTotal = 0;
        let currentSort = 'score';
        let selectedResultIndex = -1;
        let openPreviewKey = null;
        let currentDetailKind = 'function';
        let currentBinaryMd5 = null;
        let currentBinaryCompareData = null;
        let currentBinaryGraphDepth = 2;
        let currentBinaryGraphLimit = 6;
        let currentBinaryCompareLimit = 18;
        let currentBinaryCompareMode = 'all';
        let currentGraphHoverMd5 = null;
        let currentGraphFocusMd5 = null;
        let currentBinaryCompareQuery = '';
        let currentBinaryComparePage = 1;
        const BINARY_COMPARE_PAGE_SIZE = 12;
        let currentBinaryGraphZoom = 1;
        let currentBinaryGraphView = 'list';

        const isDetailPageOpen = () => el.detailPage.classList.contains('active');
        const isComparePageOpen = () => el.binaryComparePage.classList.contains('active');

        function hideFullPages() {
            el.detailPage.classList.remove('active');
            el.binaryComparePage.classList.remove('active');
        }

        function activateFullPage(kind) {
            el.dashboard.classList.add('hidden');
            el.secondary.classList.add('hidden');
            el.results.classList.remove('active');
            el.comparePanel.classList.add('hidden');
            hideFullPages();
            if (kind === 'detail') el.detailPage.classList.add('active');
            if (kind === 'compare') el.binaryComparePage.classList.add('active');
        }

        function restorePrimarySurface() {
            hideFullPages();
            if (currentQuery) {
                el.dashboard.classList.add('hidden');
                el.secondary.classList.add('hidden');
                el.results.classList.add('active');
                el.comparePanel.classList.toggle('hidden', currentSearchMode !== 'functions');
            } else {
                el.dashboard.classList.remove('hidden');
                el.secondary.classList.remove('hidden');
                el.results.classList.remove('active');
                el.comparePanel.classList.add('hidden');
            }
        }

        const pinnedKeys = new Set();
        const compareKeys = [];
        const compareItems = new Map();
        const resultPreviewCache = new Map();
        let compareBaselineKey = null;
        let draggingCompareKey = null;
        const compareHydrating = new Set();
        const expandedJumpTables = new Set();
        const collapsedSwitchGroups = new Set();
        let selectedControlFlowGroup = null;
        let selectedControlFlowRow = null;
        let selectedControlFlowCase = null;
        let controlFlowFocusMode = false;
        let compareShowAll = false;
        let compareMode = 'summary';

        let metricsPrevSnapshot = null;
        let metricsPrevTsMs = 0;
        const METRIC_SPARK_LIMIT = 24;
        const metricSparkHistory = {
            errors: [],
            timeouts: [],
            rejects: [],
            append: [],
            overflow: [],
            upstream: [],
        };
        const metricPeaks = {};

        let commentFilterKind = 'all';
        let commentSearchTerm = '';
        const collapsedCommentChunks = new Set();

        const fmt = n => Number(n).toLocaleString();
        const fmtBytes = b => {
            if (b === 0) return '0 B';
            const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(b) / Math.log(k));
            return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        };
        const fmtUptime = secs => {
            const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600), m = Math.floor((secs % 3600) / 60);
            return `${d}d ${h}h ${m}m`;
        };
        const fmtHex = v => '0x' + Number(v || 0).toString(16);
        const esc = s => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

        function fmtRelativeTs(tsSec) {
            const ts = Number(tsSec || 0);
            if (!ts) return 'unknown';
            const now = Math.floor(Date.now() / 1000);
            const delta = Math.max(0, now - ts);
            if (delta < 60) return `${delta}s ago`;
            if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
            if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
            return `${Math.floor(delta / 86400)}d ago`;
        }

        function fmtStartTime(tsSec) {
            const ts = Number(tsSec || 0);
            if (!ts) return '-';
            const d = new Date(ts * 1000);
            return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
        }

        function searchPlaceholderForMode(mode) {
            return mode === 'binaries'
                ? 'ENTER BINARY QUERY: basename, alias, or short id...'
                : 'ENTER FUNCTION QUERY: name, demangled symbol, or binary...';
        }

        function renderSortOptions() {
            if (currentSearchMode === 'binaries') {
                el.resultsSort.innerHTML = ''
                    + '<option value="score">Relevance</option>'
                    + '<option value="name">Name A-Z</option>'
                    + '<option value="functions">Function Count</option>'
                    + '<option value="versions">Version Count</option>'
                    + '<option value="recent">Most Recent</option>';
            } else {
                el.resultsSort.innerHTML = ''
                    + '<option value="score">Score (Default)</option>'
                    + '<option value="name">Name A-Z</option>'
                    + '<option value="binaries">Binaries Count</option>'
                    + '<option value="lang">Language</option>'
                    + '<option value="recent">Most Recent</option>';
            }
            el.resultsSort.value = currentSort;
        }

        function applySearchModeUi() {
            el.modeFunctions.classList.toggle('active', currentSearchMode === 'functions');
            el.modeBinaries.classList.toggle('active', currentSearchMode === 'binaries');
            el.searchEntityLabel.textContent = currentSearchMode.toUpperCase();
            el.q.placeholder = searchPlaceholderForMode(currentSearchMode);
            if (currentSearchMode === 'binaries' && currentSort === 'binaries') currentSort = 'score';
            if (currentSearchMode === 'functions' && (currentSort === 'functions' || currentSort === 'versions')) currentSort = 'score';
            renderSortOptions();
        }

        function setSearchMode(mode, rerun = true, updateUrl = true) {
            if (mode !== 'functions' && mode !== 'binaries') mode = 'functions';
            currentSearchMode = mode;
            applySearchModeUi();
            if (mode === 'binaries') {
                el.comparePanel.classList.add('hidden');
            } else if (currentQuery) {
                el.comparePanel.classList.remove('hidden');
            }
            if (rerun && currentQuery) {
                runSearch(currentQuery, 1, updateUrl);
            } else if (updateUrl) {
                syncHashWithUi();
            }
        }

        function easeOutExpo(t) {
            return t >= 1 ? 1 : 1 - Math.pow(2, -10 * t);
        }

        function counterDuration(from, to, baseDuration) {
            const delta = Math.abs(to - from);
            const magnitude = Math.max(Math.abs(from), Math.abs(to), 1);
            const scaleBoost = Math.min(1.45, 1 + (Math.log10(magnitude + 1) * 0.08));
            const deltaBoost = Math.min(1.35, 1 + (Math.log10(delta + 1) * 0.06));
            return Math.max(420, Math.min(1650, baseDuration * scaleBoost * deltaBoost));
        }

        function snapAnimatedValue(value, delta) {
            if (delta < 25) return Math.round(value);
            if (delta < 1000) return Math.round(value / 5) * 5;
            if (delta < 100000) return Math.round(value / 25) * 25;
            if (delta < 10000000) return Math.round(value / 250) * 250;
            return Math.round(value / 1000) * 1000;
        }

        function animateMetricValue(node, nextValue, formatter = fmt, duration = 900) {
            if (!node) return;
            const id = node.id || String(Math.random());
            const prev = metricAnimationState.get(id);
            const to = Number(nextValue || 0);
            const from = prev && Number.isFinite(prev.current) ? prev.current : to;
            const tunedDuration = counterDuration(from, to, duration);
            const delta = Math.abs(to - from);
            if (!Number.isFinite(to)) {
                node.textContent = formatter(nextValue);
                return;
            }
            if (Math.abs(to - from) < 0.000001) {
                node.textContent = formatter(to);
                metricAnimationState.set(id, { current: to, raf: null });
                return;
            }
            if (prev && prev.raf) cancelAnimationFrame(prev.raf);
            const start = performance.now();
            const state = { current: from, raf: null };
            const tick = now => {
                const p = Math.min(1, (now - start) / tunedDuration);
                const eased = easeOutExpo(p);
                const value = from + ((to - from) * eased);
                const snapped = snapAnimatedValue(value, delta);
                state.current = value;
                node.textContent = formatter(snapped);
                if (p < 1) state.raf = requestAnimationFrame(tick);
                else {
                    state.current = to;
                    state.raf = null;
                    node.textContent = formatter(to);
                }
            };
            metricAnimationState.set(id, state);
            state.raf = requestAnimationFrame(tick);
        }

        function fmtWholeAnimated(n) {
            return fmt(Math.round(Number(n || 0)));
        }

        function fmtBytesAnimated(n) {
            return fmtBytes(Math.max(0, Math.round(Number(n || 0))));
        }

        function detectQueryIntent(query) {
            const q = (query || '').trim();
            if (!q) return { label: 'INTENT: NONE', hint: '' };

            if (/^(0x)?[0-9a-f]{8,32}$/i.test(q)) {
                return {
                    label: 'INTENT: KEY/ADDR',
                    hint: 'Exact key/address pattern detected. Prefix scores may flatten.',
                };
            }
            if (q.includes('::') || /^_Z/.test(q) || /[<>]/.test(q)) {
                return {
                    label: 'INTENT: SYMBOL',
                    hint: 'Namespace or mangled symbol style query.',
                };
            }
            if (/[\\/]/.test(q) || /\.(exe|dll|so|dylib|bin)$/i.test(q)) {
                return {
                    label: 'INTENT: BINARY',
                    hint: 'Binary/path style query. Binary-name hits should rank strongly.',
                };
            }
            if (/\s/.test(q)) {
                return {
                    label: 'INTENT: MIXED',
                    hint: 'Multi-token query; score can favor broad lexical overlap.',
                };
            }

            return {
                label: 'INTENT: IDENTIFIER',
                hint: 'Single-token identifier search.',
            };
        }

        function buildControlFlowContext(cf) {
            const switches = Array.isArray(cf && cf.switches) ? cf.switches : [];
            const tables = Array.isArray(cf && cf.jumptables) ? cf.jumptables : [];

            function controlFlowId(kind, chunk, off) {
                return 'cf-' + String(kind || '').toLowerCase() + '-' + chunk + '-' + off;
            }

            const switchLinks = switches.map(sw => {
                let best = null;
                tables.forEach(jt => {
                    jt.refs.forEach(ref => {
                        if (ref.fchunk_nr !== sw.fchunk_nr) return;
                        const dist = Math.abs(Number(ref.fchunk_off) - Number(sw.fchunk_off));
                        if (!best || dist < best.dist) {
                            best = { addr: jt.addr, dist };
                        }
                    });
                });
                return best && best.dist <= 0x80 ? best.addr : null;
            });

            const tableSwitchCounts = new Map();
            switchLinks.forEach(addr => {
                if (!addr) return;
                tableSwitchCounts.set(addr, (tableSwitchCounts.get(addr) || 0) + 1);
            });

            const groupedSwitches = new Map();
            const rowToGroup = new Map();
            switches.forEach((sw, idx) => {
                const addr = switchLinks[idx] || '__unlinked__';
                if (!groupedSwitches.has(addr)) groupedSwitches.set(addr, []);
                groupedSwitches.get(addr).push(sw);
                rowToGroup.set(controlFlowId(sw.kind, sw.fchunk_nr, sw.fchunk_off), 'grp:' + addr);
            });

            tables.forEach(jt => {
                jt.refs.forEach(ref => {
                    rowToGroup.set(controlFlowId(ref.kind, ref.fchunk_nr, ref.fchunk_off), 'grp:' + jt.addr);
                });
            });

            return { switches, tables, switchLinks, tableSwitchCounts, groupedSwitches, rowToGroup, controlFlowId };
        }

        function renderCompactControlFlowStrip(labels, stats, groupId = null) {
            const bins = Array.isArray(labels) ? labels.slice(0, 18) : [];
            let html = '<div class="controlflow-group-strip">';
            html += '<div class="controlflow-group-strip-head">';
            html += '<div class="controlflow-group-strip-label">Case Density</div>';
            html += '<div class="controlflow-toolbar-summary">';
            stats.forEach(stat => {
                html += '<span class="frame-chip' + (stat.warn ? ' warn' : '') + '">' + esc(stat.label) + '</span>';
            });
            html += '</div></div>';
            html += '<div class="controlflow-density-strip">';
            bins.forEach(label => {
                const active = selectedControlFlowGroup === groupId && selectedControlFlowCase === label;
                html += '<button class="controlflow-density-bin fill' + (label === 'default' ? ' default' : '') + (active ? ' active' : '') + '" title="' + esc(label) + '" onclick="event.stopPropagation();setControlFlowCase(\'' + esc(groupId || '') + '\', \'' + esc(label) + '\')"></button>';
            });
            for (let i = bins.length; i < 18; i++) {
                html += '<div class="controlflow-density-bin"></div>';
            }
            html += '</div></div>';
            return html;
        }

        function controlFlowCaseMatches(ref, label) {
            if (!label) return true;
            if (!ref) return false;
            if (label === 'default') return !!ref.is_default || ref.source_role === 'default';
            return Array.isArray(ref.case_labels) && ref.case_labels.includes(label);
        }

        function estimateMetricMax(name, value) {
            const v = Number(value || 0);
            const prevPeak = metricPeaks[name] || 0;
            metricPeaks[name] = Math.max(prevPeak * 0.97, v, 1);
            return metricPeaks[name];
        }

        function setMetricIndicator(valueElement, rawValue, severity = 'normal') {
            if (!valueElement) return;
            const card = valueElement.closest('.metric-card');
            if (!card) return;
            const bars = card.querySelectorAll('.metric-indicator .bar');
            if (!bars.length) return;

            const max = estimateMetricMax(valueElement.id, rawValue);
            const ratio = Math.max(0, Math.min(1, Number(rawValue || 0) / max));
            const active = Math.max(1, Math.round(ratio * bars.length));

            bars.forEach((bar, i) => {
                bar.className = 'bar';
                if (i < active) {
                    if (severity === 'critical') bar.classList.add('crit');
                    else if (severity === 'warn') bar.classList.add('warn');
                    else bar.classList.add('active');
                }
            });
        }

        function pushSparklinePoint(key, value) {
            const arr = metricSparkHistory[key];
            if (!arr) return;
            arr.push(Number(value || 0));
            while (arr.length > METRIC_SPARK_LIMIT) arr.shift();
        }

        function toSparkline(arr) {
            if (!arr || arr.length === 0) return '';
            const chars = '▁▂▃▄▅▆▇█';
            const min = Math.min(...arr);
            const max = Math.max(...arr);
            const span = Math.max(1, max - min);
            return arr
                .map(v => {
                    const idx = Math.max(0, Math.min(chars.length - 1, Math.round(((v - min) / span) * (chars.length - 1))));
                    return chars[idx];
                })
                .join('');
        }

        function setRateText(elNode, curr, prev, dtSec, suffix = '/s') {
            if (!elNode) return;
            if (!prev || dtSec <= 0) {
                elNode.textContent = '+0.00' + suffix;
                return;
            }
            const rate = (Number(curr || 0) - Number(prev || 0)) / dtSec;
            const sign = rate >= 0 ? '+' : '';
            elNode.textContent = sign + rate.toFixed(2) + suffix;
        }

        function compareTextForKeys() {
            if (compareKeys.length === 0) return 'No functions queued';
            if (compareKeys.length === 1) return '1 function queued';
            const baseline = compareBaselineKey ? (' // baseline ' + compareBaselineKey.slice(0, 8)) : '';
            return compareKeys.length + ' functions queued' + baseline;
        }

        function compareStorageKey() {
            return 'dazhbog.compareSets.v1';
        }

        function compareStateStorageKey() {
            return 'dazhbog.compareState.v1';
        }

        function semanticNeighborPrefsStorageKey() {
            return 'dazhbog.semanticNeighbors.v1';
        }

        function loadCompareSets() {
            try {
                return JSON.parse(localStorage.getItem(compareStorageKey()) || '{}') || {};
            } catch (_) {
                return {};
            }
        }

        function storeCompareSets(sets) {
            localStorage.setItem(compareStorageKey(), JSON.stringify(sets));
        }

        function persistCompareState() {
            try {
                localStorage.setItem(compareStateStorageKey(), JSON.stringify({
                    keys: [...compareKeys],
                    baseline: compareBaselineKey,
                }));
            } catch (_) {}
        }

        function restoreCompareState() {
            try {
                const raw = localStorage.getItem(compareStateStorageKey());
                if (!raw) return;
                const state = JSON.parse(raw);
                if (!state || !Array.isArray(state.keys)) return;
                compareKeys.length = 0;
                state.keys.forEach(k => {
                    if (typeof k === 'string' && k) compareKeys.push(k);
                });
                compareBaselineKey = typeof state.baseline === 'string' ? state.baseline : (compareKeys[0] || null);
            } catch (_) {}
        }

        function persistSemanticNeighborPrefs() {
            try {
                localStorage.setItem(semanticNeighborPrefsStorageKey(), JSON.stringify({
                    limit: currentSemanticNeighborLimit,
                    strictFamily: currentSemanticNeighborStrictFamily,
                }));
            } catch (_) {}
        }

        function restoreSemanticNeighborPrefs() {
            try {
                const raw = localStorage.getItem(semanticNeighborPrefsStorageKey());
                if (!raw) return;
                const prefs = JSON.parse(raw);
                if (!prefs || typeof prefs !== 'object') return;
                if (Number.isFinite(Number(prefs.limit))) {
                    currentSemanticNeighborLimit = Math.max(1, Math.min(24, Number.parseInt(prefs.limit, 10) || 8));
                }
                if (typeof prefs.strictFamily === 'boolean') {
                    currentSemanticNeighborStrictFamily = prefs.strictFamily;
                }
            } catch (_) {}
        }

        function refreshCompareLoadOptions() {
            const sets = loadCompareSets();
            const names = Object.keys(sets).sort();
            el.compareLoad.innerHTML = '<option value="">Load Set</option>' + names.map(name => '<option value="' + esc(name) + '">' + esc(name) + '</option>').join('');
        }

        function exportCompareSet() {
            if (compareKeys.length === 0) return;
            const payload = {
                name: 'compare-set',
                exported_at: new Date().toISOString(),
                keys: [...compareKeys],
                baseline: compareBaselineKey,
            };
            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'dazhbog-compare-set.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        }

        function importCompareSetFromText(text) {
            const parsed = JSON.parse(text);
            if (!parsed || !Array.isArray(parsed.keys)) {
                throw new Error('invalid compare set file');
            }
            compareKeys.length = 0;
            parsed.keys.forEach(k => {
                if (typeof k === 'string' && k) compareKeys.push(k);
            });
            compareBaselineKey = typeof parsed.baseline === 'string' ? parsed.baseline : (compareKeys[0] || null);
            persistCompareState();
            updateCompareTray();
            renderResultsList();
            hydrateCompareItems(compareKeys);
        }

        function rememberCompareItem(hit) {
            if (!hit || !hit.key_hex) return;
            const prev = compareItems.get(hit.key_hex) || {};
            compareItems.set(hit.key_hex, {
                key_hex: hit.key_hex,
                name: hit.func_name_demangled || hit.func_name || hit.key_hex,
                ts: hit.ts || 0,
                loading: false,
                hydrated: true,
                detail: prev.detail || null,
            });
        }

        async function hydrateCompareItems(keys = compareKeys) {
            const missing = keys.filter(keyHex => {
                const item = compareItems.get(keyHex);
                return (!item || item.name === keyHex || !item.ts) && !compareHydrating.has(keyHex);
            });
            if (missing.length === 0) return;

            missing.forEach(keyHex => {
                compareHydrating.add(keyHex);
                const prev = compareItems.get(keyHex) || { key_hex: keyHex, name: keyHex, ts: 0 };
                compareItems.set(keyHex, { ...prev, loading: true });
            });
            updateCompareTray();

            await Promise.all(missing.map(async keyHex => {
                try {
                    const resp = await fetch('/api/function/' + encodeURIComponent(keyHex));
                    if (!resp.ok) return;
                    const data = await resp.json();
                    if (data && !data.error) {
                        compareItems.set(keyHex, {
                            key_hex: keyHex,
                            name: data.name || keyHex,
                            ts: data.ts || 0,
                            loading: false,
                            hydrated: true,
                            detail: data,
                        });
                    }
                } catch (_) {}
                finally {
                    compareHydrating.delete(keyHex);
                    const prev = compareItems.get(keyHex);
                    if (prev && prev.loading) {
                        compareItems.set(keyHex, { ...prev, loading: false });
                    }
                }
            }));

            updateCompareTray();
        }

        function sortHits(hits, mode) {
            const out = [...hits];
            switch (mode) {
                case 'name':
                    out.sort((a, b) => (a.display_name || a.func_name_demangled || a.func_name || '').localeCompare(b.display_name || b.func_name_demangled || b.func_name || ''));
                    break;
                case 'binaries':
                    out.sort((a, b) => (b.binary_names || []).length - (a.binary_names || []).length || b.score - a.score);
                    break;
                case 'functions':
                    out.sort((a, b) => Number(b.function_count || 0) - Number(a.function_count || 0) || b.score - a.score);
                    break;
                case 'versions':
                    out.sort((a, b) => Number(b.version_count || 0) - Number(a.version_count || 0) || b.score - a.score);
                    break;
                case 'lang':
                    out.sort((a, b) => (a.lang || 'zz').localeCompare(b.lang || 'zz') || b.score - a.score);
                    break;
                case 'recent':
                    out.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0) || b.score - a.score);
                    break;
                case 'score':
                default:
                    out.sort((a, b) => b.score - a.score);
                    break;
            }

            // Pinning always wins over current sort
            if (currentSearchMode !== 'functions') return out;
            out.sort((a, b) => {
                const ap = pinnedKeys.has(a.key_hex) ? 1 : 0;
                const bp = pinnedKeys.has(b.key_hex) ? 1 : 0;
                return bp - ap;
            });
            return out;
        }

        function setResultsIntent(query) {
            const intent = detectQueryIntent(query);
            if (currentSearchMode === 'binaries') {
                el.resultsIntent.textContent = 'INTENT: BINARY LOOKUP';
                el.resultsHint.textContent = 'Basename collisions stay grouped but individually addressable.';
                return;
            }
            el.resultsIntent.textContent = intent.label;
            el.resultsHint.textContent = intent.hint;
        }

        function normalizeScore(score, minScore, maxScore) {
            if (maxScore <= minScore) return 1;
            return Math.max(0, Math.min(1, (score - minScore) / (maxScore - minScore)));
        }

        function copyText(value) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(value).catch(() => {});
            }
        }

        function copyResultKey(keyHex) {
            copyText(keyHex);
            copiedKeyHex = keyHex;
            if (copiedKeyTimer) clearTimeout(copiedKeyTimer);
            renderResultsList();
            copiedKeyTimer = setTimeout(() => {
                copiedKeyHex = null;
                copiedKeyTimer = null;
                renderResultsList();
            }, 1200);
        }

        function updateCompareTray() {
            if (compareBaselineKey && !compareKeys.includes(compareBaselineKey)) {
                compareBaselineKey = compareKeys[0] || null;
            }
            el.compareSummary.textContent = compareTextForKeys();
            el.compareOpen.disabled = compareKeys.length < 2;
            el.comparePanel.classList.toggle('compact', compareKeys.length === 0);
            el.compareList.innerHTML = compareKeys.map(keyHex => {
                const item = compareItems.get(keyHex) || { key_hex: keyHex, name: keyHex, ts: 0, loading: false };
                const baseline = compareBaselineKey === keyHex;
                return '<div class="compare-pill' + (baseline ? ' baseline' : '') + (item.loading ? ' loading' : '') + '" draggable="true" ondragstart="startCompareDrag(\'' + esc(keyHex) + '\')" ondragover="allowCompareDrop(event)" ondrop="dropCompareKey(\'' + esc(keyHex) + '\')">'
                    + '<button class="compare-pill-handle" title="Drag to reorder">::</button>'
                    + '<div class="compare-pill-main">'
                    + '<div class="compare-pill-name">' + esc(item.name) + '</div>'
                    + '<div class="compare-pill-key">' + esc(keyHex) + (item.ts ? ' // ' + esc(fmtRelativeTs(item.ts)) : '') + '</div>'
                    + (item.loading ? '<div class="compare-pill-status">loading metadata...</div>' : '')
                    + '</div>'
                    + '<button class="compare-pill-pin' + (baseline ? ' active' : '') + '" onclick="setCompareBaseline(\'' + esc(keyHex) + '\')" title="Set baseline">B</button>'
                    + '<button class="compare-pill-remove" onclick="removeCompareKey(\'' + esc(keyHex) + '\')">x</button>'
                    + '</div>';
            }).join('');
            persistCompareState();
        }

        function setCompareShowAll(next) {
            compareShowAll = !!next;
            rerenderCompareDiff();
            syncHashWithUi();
        }

        function setCompareBaseline(keyHex) {
            compareBaselineKey = keyHex;
            updateCompareTray();
            rerenderCompareDiff();
            syncHashWithUi();
        }

        function startCompareDrag(keyHex) {
            draggingCompareKey = keyHex;
        }

        function allowCompareDrop(event) {
            event.preventDefault();
        }

        function dropCompareKey(targetKey) {
            if (!draggingCompareKey || draggingCompareKey === targetKey) return;
            const from = compareKeys.indexOf(draggingCompareKey);
            const to = compareKeys.indexOf(targetKey);
            if (from < 0 || to < 0) return;
            const [moved] = compareKeys.splice(from, 1);
            compareKeys.splice(to, 0, moved);
            draggingCompareKey = null;
            updateCompareTray();
            rerenderCompareDiff();
        }

        function saveCompareSet() {
            if (compareKeys.length === 0) return;
            const name = prompt('Save compare set as:', 'set-' + new Date().toISOString().slice(0, 10));
            if (!name) return;
            const sets = loadCompareSets();
            sets[name] = {
                keys: [...compareKeys],
                baseline: compareBaselineKey,
                saved_at: Date.now(),
            };
            storeCompareSets(sets);
            refreshCompareLoadOptions();
        }

        function loadCompareSet(name) {
            if (!name) return;
            const sets = loadCompareSets();
            const set = sets[name];
            if (!set || !Array.isArray(set.keys)) return;
            compareKeys.length = 0;
            set.keys.forEach(k => compareKeys.push(k));
            compareBaselineKey = set.baseline || compareKeys[0] || null;
            updateCompareTray();
            renderResultsList();
            hydrateCompareItems(compareKeys);
        }

        function setCompareMode(next) {
            compareMode = next === 'full' ? 'full' : 'summary';
            rerenderCompareDiff();
            syncHashWithUi();
        }

        function rerenderCompareDiff() {
            if (currentCompareRecords.length >= 2) {
                el.modalBody.innerHTML = buildStructuredDiff(currentCompareRecords);
            }
        }

        function togglePin(keyHex) {
            if (pinnedKeys.has(keyHex)) pinnedKeys.delete(keyHex);
            else pinnedKeys.add(keyHex);
            renderResultsList();
        }

        function removeCompareKey(keyHex) {
            const idx = compareKeys.indexOf(keyHex);
            if (idx >= 0) {
                compareKeys.splice(idx, 1);
            }
            updateCompareTray();
            renderResultsList();
        }

        function toggleCompareKey(keyHex) {
            const hit = currentHits.find(h => h.key_hex === keyHex);
            if (hit) rememberCompareItem(hit);
            const idx = compareKeys.indexOf(keyHex);
            if (idx >= 0) {
                compareKeys.splice(idx, 1);
            } else {
                compareKeys.push(keyHex);
                if (!compareBaselineKey) compareBaselineKey = keyHex;
            }
            updateCompareTray();
            renderResultsList();
        }

        function clearCompareKeys() {
            compareKeys.length = 0;
            compareBaselineKey = null;
            updateCompareTray();
            renderResultsList();
        }

        function openCompareModal() {
            if (compareKeys.length < 2) return;
            currentDetailData = null;
            currentDetailKeyHex = null;
            currentCompareRecords = [];
            pendingDetailSection = null;
            el.modalKey.textContent = compareKeys.length + ' FUNCTIONS';
            el.modalBody.innerHTML = '<div class="detail-loading">&gt;&gt;&gt; LOADING COMPARISON...</div>';
            activateFullPage('detail');
            syncHashWithUi();

            Promise.all(compareKeys.map(k => fetch('/api/function/' + encodeURIComponent(k)).then(r => r.json())))
                .then(records => {
                    records.forEach(rec => {
                        compareItems.set(rec.key_hex, {
                            key_hex: rec.key_hex,
                            name: rec.name,
                            ts: rec.ts || 0,
                        });
                    });
                    updateCompareTray();
                    currentCompareRecords = records;
                    syncHashWithUi();
                    rerenderCompareDiff();
                })
                .catch(err => {
                    el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>COMPARE ERROR</h3><p>' + esc(err.message || String(err)) + '</p></div>';
                });
        }

        function summaryFromMetadata(data) {
            const m = data && data.metadata ? data.metadata : null;
            return {
                typeDecl: m && m.type_parts && m.type_parts.declaration ? m.type_parts.declaration : '-',
                frameMembers: m && m.frame_desc && m.frame_desc.members ? m.frame_desc.members.length : 0,
                comments: m ? ((m.insn_cmts || []).length + (m.rpt_insn_cmts || []).length + (m.extra_cmts || []).length) : 0,
                parseState: m && m.errors && m.errors.length > 0 ? 'partial' : 'parsed',
                parseErrors: m && m.errors ? m.errors.length : 0,
                vdElapsed: m && m.vd_elapsed !== null && m.vd_elapsed !== undefined ? m.vd_elapsed : null,
                binaries: data && data.binary_names ? data.binary_names.length : 0,
                fcmt: m && m.fcmt ? m.fcmt : null,
                frptcmt: m && m.frptcmt ? m.frptcmt : null,
            };
        }

        function togglePreview(keyHex) {
            openPreviewKey = openPreviewKey === keyHex ? null : keyHex;
            renderResultsList();
            if (openPreviewKey && !resultPreviewCache.has(keyHex)) {
                fetch('/api/function/' + encodeURIComponent(keyHex))
                    .then(r => r.json())
                    .then(data => {
                        resultPreviewCache.set(keyHex, data);
                        if (openPreviewKey === keyHex) renderResultsList();
                    })
                    .catch(() => {
                        resultPreviewCache.set(keyHex, { error: 'preview unavailable' });
                        if (openPreviewKey === keyHex) renderResultsList();
                    });
            }
        }

        function previewHtmlForKey(keyHex) {
            const data = resultPreviewCache.get(keyHex);
            if (!data) return '<div class="result-preview-line">Loading preview...</div>';
            if (data.error) return '<div class="result-preview-line">Preview unavailable</div>';
            const s = summaryFromMetadata(data);
            let html = '<div class="result-preview-grid">';
            html += '<div class="result-preview-stat"><div class="label">Data Size</div><div class="value">' + fmtBytes(data.data_size || 0) + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Frame Members</div><div class="value">' + s.frameMembers + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Comments</div><div class="value">' + s.comments + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Parser State</div><div class="value">' + esc(s.parseState) + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Parser Errors</div><div class="value">' + s.parseErrors + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Binaries</div><div class="value">' + s.binaries + '</div></div>';
            html += '<div class="result-preview-stat"><div class="label">Age</div><div class="value">' + esc(fmtRelativeTs(data.ts)) + '</div></div>';
            html += '</div>';
            html += '<div class="result-preview-line"><span class="k">type</span>' + esc(s.typeDecl) + '</div>';
            if (s.vdElapsed !== null) {
                html += '<div class="result-preview-line"><span class="k">decomp</span>' + esc(String(s.vdElapsed)) + ' seconds</div>';
            }
            if (data.binary_names && data.binary_names.length > 0) {
                html += '<div class="result-preview-line"><span class="k">bins</span>' + esc(data.binary_names.slice(0, 6).join(', ')) + (data.binary_names.length > 6 ? ' ...' : '') + '</div>';
            }
            if (s.fcmt) {
                html += '<div class="result-preview-line"><span class="k">cmt</span>' + esc(s.fcmt.slice(0, 220)) + (s.fcmt.length > 220 ? ' ...' : '') + '</div>';
            }
            if (!s.fcmt && s.frptcmt) {
                html += '<div class="result-preview-line"><span class="k">rpt</span>' + esc(s.frptcmt.slice(0, 220)) + (s.frptcmt.length > 220 ? ' ...' : '') + '</div>';
            }
            return html;
        }

        function jumpToDetailSection(id) {
            const node = document.getElementById(id);
            if (node) node.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        function setActiveDetailNav(id, updateUrl = true) {
            currentDetailSection = id || null;
            document.querySelectorAll('.detail-nav button').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.target === id);
            });
            if (updateUrl) syncHashWithUi();
        }

        function activateDetailSection(id, updateUrl = true, smooth = true) {
            if (!id) return;
            const node = document.getElementById(id);
            if (node) {
                node.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' });
            }
            setActiveDetailNav(id, updateUrl);
        }

        function syncDetailSectionFromScroll() {
            if (!isDetailPageOpen() || !currentDetailKeyHex) return;
            const anchors = Array.from(el.modalBody.querySelectorAll('.detail-anchor[id]'));
            if (!anchors.length) return;
            const containerTop = el.modalBody.getBoundingClientRect().top;
            let bestId = anchors[0].id;
            let bestDist = Number.POSITIVE_INFINITY;
            anchors.forEach(node => {
                const dist = Math.abs(node.getBoundingClientRect().top - containerTop - 18);
                if (dist < bestDist) {
                    bestDist = dist;
                    bestId = node.id;
                }
            });
            if (bestId && bestId !== currentDetailSection) {
                setActiveDetailNav(bestId, true);
            }
        }

        function analyzeFrame(fd) {
            const diagnostics = [];
            if (!fd || !Array.isArray(fd.members) || fd.members.length === 0) return diagnostics;
            const members = [...fd.members]
                .filter(m => m.offset !== null && m.offset !== undefined)
                .sort((a, b) => Number(a.offset) - Number(b.offset));

            for (let i = 0; i < members.length; i++) {
                const cur = members[i];
                const curOff = Number(cur.offset || 0);
                const curSize = Math.max(1, Number(cur.nbytes || 0));
                if (!cur.nbytes) diagnostics.push({ label: 'missing size', kind: 'warn' });
                if (curOff + curSize > Number(fd.frsize || 0) && Number(fd.frsize || 0) > 0) diagnostics.push({ label: 'out of frame', kind: 'warn' });
                if (i > 0) {
                    const prev = members[i - 1];
                    const prevEnd = Number(prev.offset || 0) + Math.max(1, Number(prev.nbytes || 0));
                    if (curOff < prevEnd) diagnostics.push({ label: 'overlap', kind: 'warn' });
                    if (curOff > prevEnd) diagnostics.push({ label: 'gap', kind: 'normal' });
                }
            }
            return diagnostics;
        }

        function renderFrameDiagnostics(fd) {
            const diagnostics = analyzeFrame(fd);
            if (diagnostics.length === 0) {
                return '<div class="frame-diagnostics"><span class="frame-chip">layout coherent</span></div>';
            }
            return '<div class="frame-diagnostics">' + diagnostics.map(d => '<span class="frame-chip' + (d.kind === 'warn' ? ' warn' : '') + '">' + esc(d.label) + '</span>').join('') + '</div>';
        }

        function renderControlFlowMetadata(cf) {
            const ctx = buildControlFlowContext(cf);
            const switches = ctx.switches;
            const tables = ctx.tables;
            if (switches.length === 0 && tables.length === 0) {
                return '<div class="metadata-empty">No switch or jumptable annotations</div>';
            }

            function summarizeRelation(ref) {
                if (ref.source_role === 'default') return 'Default arm';
                if (ref.source_role === 'case' && ref.case_labels && ref.case_labels.length) {
                    return ref.case_labels.length + ' case bucket' + (ref.case_labels.length === 1 ? '' : 's');
                }
                return 'Entry site';
            }

            const switchLinks = ctx.switchLinks;
            const tableSwitchCounts = ctx.tableSwitchCounts;
            const groupedSwitches = ctx.groupedSwitches;
            const controlFlowId = ctx.controlFlowId;

            function renderCopyButton(label, value) {
                return '<button class="controlflow-toggle" onclick="event.stopPropagation();copyText(\'' + esc(value) + '\')">' + esc(label) + '</button>';
            }

            function renderCaseChip(label, groupId = null) {
                const active = selectedControlFlowCase === label;
                const cls = 'case-chip' + (label === 'default' ? ' default' : '') + (active ? ' active' : '');
                if (!groupId) return '<span class="' + cls + '">' + esc(label) + '</span>';
                return '<button class="' + cls + '" onclick="event.stopPropagation();setControlFlowCase(\'' + esc(groupId) + '\', \'' + esc(label) + '\')">' + esc(label) + '</button>';
            }

            let html = '';
            html += '<div class="controlflow-legend">';
            html += '<span class="frame-chip">entry</span><span class="frame-chip">case</span><span class="frame-chip warn">default</span><span class="comment-kind">REG</span><span class="comment-kind repeatable">RPT</span>';
            html += '</div>';
            html += '<div class="controlflow-toolbar">';
            html += '<div class="controlflow-toolbar-summary">';
            html += '<span class="frame-chip">' + esc(String(groupedSwitches.size)) + ' groups</span>';
            html += '<span class="frame-chip">' + esc(String(switches.length)) + ' switch sites</span>';
            html += '<span class="frame-chip">' + esc(String(tables.length)) + ' jump tables</span>';
            if (selectedControlFlowGroup) html += '<span class="controlflow-focus-note">selection ' + esc(selectedControlFlowGroup.replace(/^grp:/, '')) + '</span>';
            if (selectedControlFlowCase) html += '<span class="controlflow-active-filter">' + renderCaseChip(selectedControlFlowCase, selectedControlFlowGroup) + '<button class="controlflow-toggle" onclick="event.stopPropagation();clearControlFlowCase()">Clear Case</button></span>';
            html += '</div>';
            html += '<div class="controlflow-toolbar-actions">';
            html += '<button class="controlflow-toggle" onclick="event.stopPropagation();toggleControlFlowFocusMode()">' + (controlFlowFocusMode ? 'Exit Focus Mode' : 'Focus Selection') + '</button>';
            html += '<button class="controlflow-toggle" onclick="event.stopPropagation();clearControlFlowSelection()">Clear</button>';
            html += '</div></div>';
            if (cf.dominant) {
                html += '<div class="controlflow-hero">';
                html += '<div class="controlflow-hero-title">Dominant Switch Cluster</div>';
                html += '<div class="controlflow-hero-main">';
                html += '<div class="controlflow-hero-addr">' + esc(cf.dominant.addr) + '</div>';
                html += '<div class="controlflow-hero-stats">';
                html += '<span class="frame-chip warn">' + esc(String(cf.dominant.ref_count)) + ' grouped refs</span>';
                html += '<span class="frame-chip warn">' + esc(String(cf.dominant.case_count)) + ' cases</span>';
                cf.dominant.labels.forEach(label => {
                    html += renderCaseChip(label, 'grp:' + cf.dominant.addr);
                });
                html += '</div></div></div>';
            }

            if (groupedSwitches.size > 1 || tables.length > 1) {
                html += '<div class="controlflow-matrix">';
                html += '<div class="controlflow-matrix-row"><div class="controlflow-matrix-cell"><div class="controlflow-matrix-label">Switch Groups</div></div><div class="controlflow-matrix-cell"><div class="controlflow-matrix-value">' + esc(String(groupedSwitches.size)) + '</div></div></div>';
                html += '<div class="controlflow-matrix-row"><div class="controlflow-matrix-cell"><div class="controlflow-matrix-label">Jump Tables</div></div><div class="controlflow-matrix-cell"><div class="controlflow-matrix-value">' + esc(String(tables.length)) + '</div></div></div>';
                Array.from(groupedSwitches.entries()).forEach(([addr, group], idx) => {
                    const label = addr === '__unlinked__' ? 'Unlinked switches' : ('Group ' + (idx + 1));
                    const value = addr === '__unlinked__'
                        ? (group.length + ' switch sites')
                        : (addr + ' // ' + group.length + ' switch sites');
                    const groupId = 'grp:' + addr;
                    html += '<div class="controlflow-matrix-row' + (selectedControlFlowGroup === groupId ? ' active' : '') + '" onclick="setControlFlowGroup(\'' + groupId + '\')"><div class="controlflow-matrix-cell"><div class="controlflow-matrix-label">' + esc(label) + '</div></div><div class="controlflow-matrix-cell"><div class="controlflow-matrix-value">' + esc(value) + '</div></div></div>';
                });
                html += '</div>';
            }

            html += '<div class="controlflow-grid">';
            html += '<div class="controlflow-panel"><div class="detail-label">Switch Sites</div><div class="controlflow-stack">';
            if (switches.length === 0) {
                html += '<div class="metadata-empty">No explicit switch comments</div>';
            } else {
                Array.from(groupedSwitches.entries()).forEach(([addr, group], groupIdx) => {
                    const groupId = 'swgrp-' + groupIdx;
                    const filterId = 'grp:' + addr;
                    const linkedTable = addr === '__unlinked__' ? null : tables.find(jt => jt.addr === addr);
                    if (controlFlowFocusMode && selectedControlFlowGroup && selectedControlFlowGroup !== filterId) return;
                    const collapsed = collapsedSwitchGroups.has(groupId);
                    const dimmed = selectedControlFlowGroup && selectedControlFlowGroup !== filterId;
                    html += '<div class="switch-group' + (collapsed ? ' collapsed' : '') + (dimmed ? ' dimmed' : '') + '">';
                    html += '<div class="switch-group-head" onclick="toggleSwitchGroup(\'' + groupId + '\')">';
                    html += '<span class="switch-group-title">' + (addr === '__unlinked__' ? 'Unlinked Switches' : ('Switch Cluster ' + (groupIdx + 1))) + '</span>';
                    html += '<span class="switch-meta">' + esc(String(group.length)) + ' sites' + (addr !== '__unlinked__' ? (' // ' + addr) : '') + '</span>';
                    html += '</div>';
                    if (linkedTable) {
                        html += renderCompactControlFlowStrip(linkedTable.coverage_runs || linkedTable.all_case_labels || [], [
                            { label: String(linkedTable.case_count || 0) + ' cases' },
                            { label: String(linkedTable.refs.length || 0) + ' refs' },
                            { label: linkedTable.has_default ? 'default path' : 'no default', warn: !!linkedTable.has_default },
                            { label: linkedTable.sparse ? 'sparse' : 'dense', warn: !!linkedTable.sparse },
                        ], filterId);
                    } else {
                        html += renderCompactControlFlowStrip([], [
                            { label: String(group.length) + ' sites' },
                            { label: 'unlinked', warn: true },
                        ], filterId);
                    }
                    html += '<div class="switch-group-body">';
                    group.forEach(sw => {
                        const linkAddr = addr === '__unlinked__' ? null : addr;
                        const rowId = controlFlowId(sw.kind, sw.fchunk_nr, sw.fchunk_off);
                        html += '<div class="switch-card' + (linkAddr ? ' linked' : '') + (selectedControlFlowRow === rowId ? ' active' : '') + '" data-controlflow-id="' + rowId + '" onmouseenter="hoverControlFlowLink(\'' + rowId + '\')" onmouseleave="clearControlFlowHover()" onclick="selectControlFlowRow(\'' + rowId + '\', \'' + filterId + '\')">';
                        html += '<div class="switch-card-head"><span class="switch-title">' + esc(sw.kind) + ' switch</span><span class="switch-meta">chunk ' + esc(String(sw.fchunk_nr)) + ' @ ' + esc(fmtHex(sw.fchunk_off)) + '</span></div>';
                        html += '<div class="switch-desc">' + esc(sw.description) + '</div>';
                        html += '<div class="switch-summary"><span class="frame-chip">' + (sw.description.includes('jump') ? 'jump site' : 'case site') + '</span></div>';
                        if (linkAddr) {
                            html += '<div class="switch-links"><span class="frame-chip">table ' + esc(linkAddr) + '</span><button class="controlflow-toggle" onclick="event.stopPropagation();jumpToControlFlowTable(\'' + esc(linkAddr) + '\')">Open Table</button></div>';
                        }
                        html += '</div>';
                    });
                    html += '</div></div>';
                });
            }
            html += '</div></div>';

            html += '<div class="controlflow-panel"><div class="detail-label">Jump Tables</div><div class="controlflow-stack">';
            if (tables.length === 0) {
                html += '<div class="metadata-empty">No jumptable comments</div>';
            } else {
                tables.forEach(jt => {
                    if (controlFlowFocusMode && selectedControlFlowGroup && selectedControlFlowGroup !== ('grp:' + jt.addr)) return;
                    const expanded = expandedJumpTables.has(jt.addr);
                    const filteredRefs = selectedControlFlowCase && selectedControlFlowGroup === ('grp:' + jt.addr)
                        ? jt.refs.filter(ref => controlFlowCaseMatches(ref, selectedControlFlowCase))
                        : jt.refs;
                    const visibleRefs = expanded ? filteredRefs : filteredRefs.slice(0, 6);
                    const dimmed = selectedControlFlowGroup && selectedControlFlowGroup !== ('grp:' + jt.addr);
                    html += '<div class="jumptable-card' + (dimmed ? ' dimmed' : '') + '" id="jt-' + esc(jt.addr) + '">';
                    html += '<div class="jumptable-head">';
                    html += '<div class="jumptable-title">' + esc(jt.addr) + '</div>';
                    html += '<div class="jumptable-badges">';
                    html += '<span class="frame-chip">' + esc(String(jt.refs.length)) + ' refs</span>';
                    html += '<span class="frame-chip">' + esc(String(jt.case_count)) + ' cases</span>';
                    if (tableSwitchCounts.get(jt.addr)) html += '<span class="frame-chip">' + esc(String(tableSwitchCounts.get(jt.addr))) + ' linked switches</span>';
                    if (jt.sparse) html += '<span class="frame-chip warn">sparse</span>';
                    if (jt.has_default) html += '<span class="frame-chip warn">default case</span>';
                    html += '</div></div>';
                    html += '<div class="controlflow-actions">' + renderCopyButton('Copy Addr', jt.addr) + renderCopyButton('Copy Cases', (jt.all_case_labels || []).join(', ')) + '<button class="controlflow-toggle" onclick="event.stopPropagation();openAllJumpRefs(\'' + esc(jt.addr) + '\')">Open All Refs</button></div>';
                    html += '<div class="jumptable-coverage">';
                    html += '<div class="detail-label" style="margin:0;">Case Coverage</div>';
                    if (jt.coverage_runs && jt.coverage_runs.length > 0) {
                        html += '<div class="coverage-meta">' + jt.coverage_runs.map(label => renderCaseChip(label, 'grp:' + jt.addr)).join('') + '</div>';
                        html += '<div class="jumptable-coverage-strip">';
                        const bins = jt.coverage_runs.slice(0, 24);
                        bins.forEach(label => {
                            html += '<div class="coverage-bin fill' + (label === 'default' ? ' default' : '') + (selectedControlFlowCase === label ? ' active' : '') + '" title="' + esc(label) + '"></div>';
                        });
                        for (let i = bins.length; i < 24; i++) {
                            html += '<div class="coverage-bin"></div>';
                        }
                        html += '</div>';
                    } else {
                        html += '<div class="metadata-empty">No parsed case intervals</div>';
                    }
                    html += '</div>';
                    if (jt.all_case_labels && jt.all_case_labels.length > 0) {
                        html += '<div class="jumptable-cluster-note">Cluster cases</div>';
                        html += '<div class="jumptable-case-strip" style="padding:0 12px 8px;">' + jt.all_case_labels.map(label => renderCaseChip(label, 'grp:' + jt.addr)).join('') + '</div>';
                    }
                    html += '<div class="jumptable-ref-list">';
                    visibleRefs.forEach(ref => {
                        const rowId = controlFlowId(ref.kind, ref.fchunk_nr, ref.fchunk_off);
                        html += '<div class="jumptable-ref' + (selectedControlFlowRow === rowId ? ' active' : '') + '" data-controlflow-id="' + rowId + '" onmouseenter="hoverControlFlowLink(\'' + rowId + '\')" onmouseleave="clearControlFlowHover()" onclick="selectControlFlowRow(\'' + rowId + '\', \'' + ('grp:' + jt.addr) + '\')">';
                        html += '<div class="jumptable-ref-meta">' + esc(ref.kind) + '<br>chunk ' + esc(String(ref.fchunk_nr)) + '<br>@ <a href="javascript:void(0)" onclick="event.stopPropagation();focusCommentRow(&quot;' + rowId + '&quot;, null, true);activateDetailSection(&quot;section-comments&quot;);" style="color:var(--accent);text-decoration:none;">' + esc(fmtHex(ref.fchunk_off)) + '</a></div>';
                        html += '<div class="jumptable-ref-body"><div class="relation-summary"><span class="frame-chip">' + esc(ref.source_role) + '</span><span class="frame-chip">' + esc(summarizeRelation(ref)) + '</span></div>';
                        if (ref.case_labels && ref.case_labels.length > 0) {
                            html += '<div class="jumptable-case-strip">' + ref.case_labels.map(label => renderCaseChip(label, 'grp:' + jt.addr)).join('') + '</div>';
                        }
                        if (ref.lane_size && ref.lane_size > 1) {
                            html += '<div class="jumptable-cluster-note">cluster lane x' + esc(String(ref.lane_size)) + '</div>';
                        }
                        html += '<div class="relation-detail">' + esc(ref.kind) + ' source at chunk ' + esc(String(ref.fchunk_nr)) + ' offset ' + esc(fmtHex(ref.fchunk_off)) + '</div>';
                        html += '</div>';
                        html += '</div>';
                    });
                    if (visibleRefs.length === 0) {
                        html += '<div class="metadata-empty" style="padding:10px 12px;">No refs for selected case bin</div>';
                    }
                    html += '</div>';
                    if (filteredRefs.length > 6) {
                        html += '<div class="jumptable-more"><button class="controlflow-toggle" onclick="event.stopPropagation();toggleJumpTableExpand(&quot;' + esc(jt.addr) + '&quot;)">' + (expanded ? 'Show Less' : ('Show All ' + filteredRefs.length + ' Refs')) + '</button></div>';
                    }
                    html += '<div class="jumptable-graph">';
                    html += '<div class="jumptable-graph-node root"><div class="jumptable-graph-label">Jump Table</div><div class="jumptable-graph-value">' + esc(jt.addr) + '</div></div>';
                    html += '<div class="jumptable-graph-edge">';
                    filteredRefs.slice(0, 8).forEach(ref => {
                        const isActive = selectedControlFlowRow === controlFlowId(ref.kind, ref.fchunk_nr, ref.fchunk_off);
                        html += '<div class="jumptable-graph-node' + (isActive ? ' active' : '') + '"><div class="jumptable-graph-label">' + esc(ref.kind) + ' source</div><div class="jumptable-graph-value">chunk ' + esc(String(ref.fchunk_nr)) + ' @ ' + esc(fmtHex(ref.fchunk_off)) + (ref.case_labels && ref.case_labels.length ? ' // ' + esc(ref.case_labels.join(', ')) : '') + '</div><div class="jumptable-graph-badges"><span class="frame-chip">' + esc(ref.source_role) + '</span>' + (ref.is_default ? '<span class="frame-chip warn">default</span>' : '') + (ref.lane_size && ref.lane_size > 1 ? '<span class="frame-chip">lane x' + esc(String(ref.lane_size)) + '</span>' : '') + (ref.case_labels && ref.case_labels[0] ? renderCaseChip(ref.case_labels[0], 'grp:' + jt.addr) : '') + '</div></div>';
                    });
                    if (filteredRefs.length > 8) {
                        html += '<div class="jumptable-graph-node"><div class="jumptable-graph-value">+' + esc(String(filteredRefs.length - 8)) + ' more refs</div></div>';
                    }
                    html += '</div></div></div>';
                });
            }
            html += '</div></div>';
            html += '</div>';
            return html;
        }

        function normalizeFrameMembers(fd) {
            const members = fd && Array.isArray(fd.members) ? fd.members : [];
            return [...members]
                .map((m, i) => ({
                    key: ((m.offset ?? 'na') + ':' + (m.name || ('#' + i))),
                    name: m.name || ('member_' + i),
                    offset: m.offset ?? null,
                    size: m.nbytes ?? null,
                    type: m.tinfo && m.tinfo.declaration ? m.tinfo.declaration : '-',
                    cmt: m.cmt || '',
                    rptcmt: m.rptcmt || '',
                }))
                .sort((a, b) => {
                    const ao = a.offset === null ? Number.MAX_SAFE_INTEGER : Number(a.offset);
                    const bo = b.offset === null ? Number.MAX_SAFE_INTEGER : Number(b.offset);
                    if (ao !== bo) return ao - bo;
                    return a.name.localeCompare(b.name);
                });
        }

        function normalizeCommentEvents(metadata) {
            const reg = Array.isArray(metadata && metadata.insn_cmts) ? metadata.insn_cmts : [];
            const rpt = Array.isArray(metadata && metadata.rpt_insn_cmts) ? metadata.rpt_insn_cmts : [];
            const events = [];
            reg.forEach(c => events.push({ key: 'reg:' + c.fchunk_nr + ':' + c.fchunk_off + ':' + c.cmt, kind: 'REG', chunk: c.fchunk_nr, off: c.fchunk_off, cmt: c.cmt }));
            rpt.forEach(c => events.push({ key: 'rpt:' + c.fchunk_nr + ':' + c.fchunk_off + ':' + c.cmt, kind: 'RPT', chunk: c.fchunk_nr, off: c.fchunk_off, cmt: c.cmt }));
            return events.sort((a, b) => a.chunk - b.chunk || a.off - b.off || a.kind.localeCompare(b.kind));
        }

        function renderCompareSubsection(title, rows) {
            if (!rows.length) return '';
            return '<div class="compare-subsection"><div class="compare-subtitle">' + esc(title) + '</div>' + rows.join('') + '</div>';
        }

        function multiJump(section) {
            return currentCompareRecords.map(rec => ({ key: rec.key_hex, section }));
        }

        function renderMatrixRow(label, values, options = {}) {
            const mode = options.mode || 'generic';
            const normalized = values.map(v => String(v || '-'));
            const baseline = normalized[0] || '-';
            const unchanged = normalized.every(v => v === baseline);
            const jumps = options.jumps || [];
            const classes = ['compare-row'];
            if (!compareShowAll && unchanged) classes.push('unchanged');
            let html = '<div class="' + classes.join(' ') + '">';
            html += '<div class="compare-label">' + esc(label) + '</div>';
            normalized.forEach((value, idx) => {
                const diff = idx > 0 && value !== baseline;
                const rendered = idx === 0 || !diff ? esc(value) : diffTokenHtml(baseline, value, mode).rightHtml;
                const jump = jumps[idx];
                const click = jump ? ' onclick="event.stopPropagation();showFunctionDetail(\'' + esc(jump.key) + '\', \'' + esc(jump.section) + '\')"' : '';
                html += '<div class="compare-cell' + (diff ? ' diff' : '') + (jump ? ' jumpable' : '') + '"' + click + '>' + rendered + '</div>';
            });
            html += '</div>';
            return html;
        }

        function renderSignatureDiff(records) {
            const parsed = records.map(r => parseDecodedSignature((summaryFromMetadata(r).typeDecl || '')));
            const typeDecls = records.map(r => summaryFromMetadata(r).typeDecl || '-');
            const jumps = multiJump('section-type');
            const rows = [
                renderMatrixRow('Declaration', typeDecls, { mode: 'type', jumps }),
                renderMatrixRow('Return Type', parsed.map(p => p ? p.returnType : '-'), { mode: 'type', jumps }),
                renderMatrixRow('Call Conv', parsed.map(p => p ? (p.cc || 'default') : '-'), { jumps }),
                renderMatrixRow('Return Loc', parsed.map(p => p ? (p.retLoc || '-') : '-'), { jumps }),
            ];
            if (compareMode === 'full') {
                const maxArgs = Math.max(...parsed.map(p => p ? p.args.length : 0), 0);
                for (let i = 0; i < maxArgs; i++) {
                    rows.push(renderMatrixRow('Arg ' + i, parsed.map(p => p && p.args[i] ? p.args[i] : '-'), { mode: 'type', jumps }));
                }
            }
            return renderCompareSection('Type Signature', rows);
        }

        function renderFrameMemberDiff(records) {
            const frames = records.map(r => r.metadata && r.metadata.frame_desc ? r.metadata.frame_desc : {});
            const normalized = frames.map(fd => normalizeFrameMembers(fd));
            const rowKeys = [];
            const rowMap = new Map();

            normalized.forEach(members => {
                members.forEach(m => {
                    const key = (m.offset !== null ? 'off:' + m.offset : 'name:' + m.name);
                    if (!rowMap.has(key)) {
                        rowMap.set(key, true);
                        rowKeys.push(key);
                    }
                });
            });

            rowKeys.sort((a, b) => {
                const ao = a.startsWith('off:') ? Number(a.slice(4)) : Number.MAX_SAFE_INTEGER;
                const bo = b.startsWith('off:') ? Number(b.slice(4)) : Number.MAX_SAFE_INTEGER;
                if (ao !== bo) return ao - bo;
                return a.localeCompare(b);
            });

            const jumps = multiJump('section-frame');
            const rows = [
                renderMatrixRow('Members', normalized.map(m => String(m.length)), { jumps }),
                renderMatrixRow('Frame Size', frames.map(fd => fmtHex(fd.frsize)), { jumps }),
                renderMatrixRow('Arg Size', frames.map(fd => fmtHex(fd.argsize)), { jumps }),
                renderMatrixRow('Diagnostics', frames.map(fd => analyzeFrame(fd).map(x => x.label).join(', ') || 'layout coherent'), { jumps }),
            ];

            if (compareMode === 'full') {
                rowKeys.forEach((key, i) => {
                    const vals = normalized.map(members => {
                        const found = members.find(m => (m.offset !== null ? 'off:' + m.offset : 'name:' + m.name) === key)
                            || members.find(m => key.startsWith('off:') && m.offset === Number(key.slice(4)));
                        if (!found) return '-';
                        return (found.offset !== null ? fmtHex(found.offset) : '-') + ' ' + found.name + ' : ' + found.type + (found.size !== null ? ' [' + fmtHex(found.size) + ']' : '') + (found.cmt ? ' // ' + found.cmt : '');
                    });
                    rows.push(renderMatrixRow('Member ' + i, vals, { mode: 'type', jumps }));
                });
            }
            return renderCompareSection('Frame Layout', rows);
        }

        function renderCommentDiff(records) {
            const metas = records.map(r => r.metadata || {});
            const eventsByRecord = metas.map(m => normalizeCommentEvents(m));
            const jumps = multiJump('section-comments');
            const rows = [
                renderMatrixRow('Total Comments', eventsByRecord.map(e => String(e.length)), { jumps }),
                renderMatrixRow('Regular Comment', metas.map(m => m.fcmt || '-'), { mode: 'comment', jumps }),
                renderMatrixRow('Repeatable Comment', metas.map(m => m.frptcmt || '-'), { mode: 'comment', jumps }),
            ];

            if (compareMode === 'full') {
                const eventKeys = [];
                const seen = new Set();
                eventsByRecord.forEach(events => {
                    events.forEach(e => {
                        const key = e.kind + ':' + e.chunk + ':' + e.off;
                        if (!seen.has(key)) {
                            seen.add(key);
                            eventKeys.push(key);
                        }
                    });
                });
                eventKeys.sort((a, b) => {
                    const [ak, ac, ao] = a.split(':');
                    const [bk, bc, bo] = b.split(':');
                    return Number(ac) - Number(bc) || Number(ao) - Number(bo) || ak.localeCompare(bk);
                });

                eventKeys.slice(0, 24).forEach(key => {
                    const [kind, chunk, off] = key.split(':');
                    const vals = eventsByRecord.map(events => {
                        const ev = events.find(e => e.kind === kind && String(e.chunk) === chunk && String(e.off) === off);
                        return ev ? ev.cmt : '-';
                    });
                    rows.push(renderMatrixRow('Chunk ' + chunk + ' @ ' + fmtHex(Number(off)) + ' [' + kind + ']', vals, { mode: 'comment', jumps }));
                });
            }

            return renderCompareSection('Comments', rows);
        }

        function compareValue(a, b) {
            return String(a || '') !== String(b || '');
        }

        function tokenizeForDiff(text, mode = 'generic') {
            const s = String(text || '-');
            if (mode === 'comment') {
                return s.match(/\s+|\w+|[^\w\s]/g) || [s];
            }
            if (mode === 'type') {
                return s.match(/\s+|::|->|=>|@<|>|<|\w+|[^\w\s]/g) || [s];
            }
            return s.match(/\s+|\w+|[^\w\s]/g) || [s];
        }

        function diffTokenHtml(left, right, mode = 'generic') {
            const a = tokenizeForDiff(left, mode);
            const b = tokenizeForDiff(right, mode);
            const m = a.length;
            const n = b.length;
            const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

            for (let i = m - 1; i >= 0; i--) {
                for (let j = n - 1; j >= 0; j--) {
                    dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
                }
            }

            let i = 0;
            let j = 0;
            let leftHtml = '';
            let rightHtml = '';
            while (i < m && j < n) {
                if (a[i] === b[j]) {
                    const t = esc(a[i]);
                    leftHtml += t;
                    rightHtml += t;
                    i++;
                    j++;
                } else if (dp[i + 1][j] >= dp[i][j + 1]) {
                    leftHtml += '<span class="diff-del">' + esc(a[i]) + '</span>';
                    i++;
                } else {
                    rightHtml += '<span class="diff-add">' + esc(b[j]) + '</span>';
                    j++;
                }
            }
            while (i < m) {
                leftHtml += '<span class="diff-del">' + esc(a[i]) + '</span>';
                i++;
            }
            while (j < n) {
                rightHtml += '<span class="diff-add">' + esc(b[j]) + '</span>';
                j++;
            }

            return { leftHtml, rightHtml };
        }

        function compareRow(label, left, right, options = {}) {
            const diff = compareValue(left, right);
            const mode = options.mode || 'generic';
            const rendered = diff ? diffTokenHtml(left, right, mode) : { leftHtml: esc(String(left || '-')), rightHtml: esc(String(right || '-')) };
            const jumpable = options.leftJump || options.rightJump;
            const classes = ['compare-row'];
            if (jumpable) classes.push('jumpable');
            if (!diff) classes.push('unchanged');
            const leftClick = options.leftJump ? ' onclick="event.stopPropagation();showFunctionDetail(\'' + esc(options.leftJump.key) + '\', \'' + esc(options.leftJump.section) + '\')"' : '';
            const rightClick = options.rightJump ? ' onclick="event.stopPropagation();showFunctionDetail(\'' + esc(options.rightJump.key) + '\', \'' + esc(options.rightJump.section) + '\')"' : '';
            const labelExtra = jumpable ? '<div style="margin-top:4px;font-size:9px;color:var(--text-tertiary);">jump: ' + (options.leftJump ? 'L' : '-') + ' / ' + (options.rightJump ? 'R' : '-') + '</div>' : '';
            return '<div class="' + classes.join(' ') + '">'
                + '<div class="compare-cell' + (diff ? ' diff' : '') + '"' + leftClick + '>' + rendered.leftHtml + '</div>'
                + '<div class="compare-label">' + esc(label) + labelExtra + '</div>'
                + '<div class="compare-cell' + (diff ? ' diff' : '') + '"' + rightClick + '>' + rendered.rightHtml + '</div>'
                + '</div>';
        }

        function renderCompareSection(title, rows) {
            return '<div class="compare-section" style="--compare-cols:' + currentCompareRecords.length + ';"><div class="compare-section-title">' + esc(title) + '</div>' + rows.join('') + '</div>';
        }

        function buildStructuredDiff(records) {
            const ordered = [...records];
            const baselineIndex = compareBaselineKey ? ordered.findIndex(r => r.key_hex === compareBaselineKey) : 0;
            if (baselineIndex > 0) {
                const [baseline] = ordered.splice(baselineIndex, 1);
                ordered.unshift(baseline);
            }
            const summaries = ordered.map(summaryFromMetadata);
            const metas = ordered.map(r => r.metadata || {});
            let html = '<div class="compare-diff' + (compareShowAll ? ' show-all' : '') + '">';
            html += '<div class="compare-toolbar">';
            html += '<div class="compare-toolbar-group">';
            html += '<button class="compare-toggle' + (compareMode === 'summary' ? ' active' : '') + '" onclick="setCompareMode(\'summary\')">Summary</button>';
            html += '<button class="compare-toggle' + (compareMode === 'full' ? ' active' : '') + '" onclick="setCompareMode(\'full\')">Full Diff</button>';
            html += '<button class="compare-toggle' + (compareShowAll ? ' active' : '') + '" onclick="setCompareShowAll(' + (!compareShowAll) + ')">' + (compareShowAll ? 'Hide Unchanged' : 'Show Unchanged') + '</button>';
            html += '</div>';
            html += '<div class="compare-status">' + ordered.length + ' functions // ' + esc(compareMode) + ' mode // baseline first</div>';
            html += '</div>';
            html += '<div class="compare-head" style="--compare-cols:' + ordered.length + ';"><div class="compare-head-cell center">Field</div>';
            ordered.forEach((rec, idx) => {
                html += '<div class="compare-head-cell"><div class="compare-name">' + esc(rec.name) + (idx === 0 ? ' [baseline]' : '') + '</div><div class="compare-key">' + esc(rec.key_hex) + '</div></div>';
            });
            html += '</div>';

            html += renderCompareSection('Identity', [
                renderMatrixRow('Age', ordered.map(r => fmtRelativeTs(r.ts))),
                renderMatrixRow('Data Size', ordered.map(r => fmtBytes(r.data_size || 0))),
                renderMatrixRow('Binary Count', ordered.map(r => String((r.binary_names || []).length))),
                renderMatrixRow('Binaries', ordered.map(r => (r.binary_names || []).join(', '))),
            ]);

            currentCompareRecords = ordered;
            html += renderSignatureDiff(ordered);

            html += renderFrameMemberDiff(ordered);

            html += renderCommentDiff(ordered);

            html += renderCompareSection('Parser', [
                renderMatrixRow('Bytes Parsed', metas.map(m => String(m.bytes_parsed || 0))),
                renderMatrixRow('Raw Size', metas.map(m => fmtBytes(m.raw_size || 0))),
                renderMatrixRow('Raw Chunks', metas.map(m => String(m.raw_chunk_count || ((m.raw_chunks || []).length || 0))), { jumps: multiJump('section-semantic') }),
                renderMatrixRow('Extra Comments', metas.map(m => String((m.extra_cmts || []).length)), { jumps: multiJump('section-semantic') }),
                renderMatrixRow('Error List', metas.map(m => (m.errors || []).join(' | ') || '-'), { mode: 'comment' }),
            ]);

            html += '</div>';
            return html;
        }

        function renderFrameDescriptor(fd) {
            const members = Array.isArray(fd.members) ? [...fd.members] : [];
            if (members.length === 0) {
                return '<div class="metadata-empty">No frame members</div>';
            }

            members.sort((a, b) => {
                const ao = (a.offset === null || a.offset === undefined) ? Number.MAX_SAFE_INTEGER : Number(a.offset);
                const bo = (b.offset === null || b.offset === undefined) ? Number.MAX_SAFE_INTEGER : Number(b.offset);
                if (ao !== bo) return ao - bo;
                const as = (a.nbytes === null || a.nbytes === undefined) ? 0 : Number(a.nbytes);
                const bs = (b.nbytes === null || b.nbytes === undefined) ? 0 : Number(b.nbytes);
                return bs - as;
            });

            const frameSize = Number(fd.frsize || 0);
            const derivedSize = members.reduce((max, mem) => {
                const off = (mem.offset === null || mem.offset === undefined) ? 0 : Number(mem.offset);
                const sz = (mem.nbytes === null || mem.nbytes === undefined) ? 1 : Math.max(1, Number(mem.nbytes));
                return Math.max(max, off + sz);
            }, 1);
            const scaleSize = Math.max(frameSize, derivedSize, 1);

            let html = '<div class="frame-viz">';
            html += '<div class="frame-map">';
            html += '<div class="frame-map-track">';

            members.forEach((mem, i) => {
                const hasOffset = mem.offset !== null && mem.offset !== undefined;
                const hasSize = mem.nbytes !== null && mem.nbytes !== undefined;
                const off = hasOffset ? Number(mem.offset) : 0;
                const size = hasSize ? Math.max(1, Number(mem.nbytes)) : 1;

                let leftPct = Math.max(0, Math.min(100, (off / scaleSize) * 100));
                let widthPct = Math.max(1.2, (size / scaleSize) * 100);
                if (leftPct + widthPct > 100) {
                    widthPct = Math.max(1.2, 100 - leftPct);
                }

                const label = mem.name ? mem.name : ('m' + i);
                const isSelf = mem.name && mem.name.toLowerCase() === 'self';
                const tooltip = 'Member ' + i
                    + (mem.name ? ' (' + mem.name + ')' : '')
                    + (hasOffset ? ' | off ' + fmtHex(off) : '')
                    + (hasSize ? ' | size ' + fmtHex(size) : '');

                html += '<div class="frame-segment' + (isSelf ? ' frame-segment-self' : '') + '" style="left:' + leftPct.toFixed(2) + '%;width:' + widthPct.toFixed(2) + '%;" title="' + esc(tooltip) + '">';
                html += '<span>' + esc(label) + '</span>';
                html += '</div>';
            });

            html += '</div>';
            html += '<div class="frame-map-scale"><span>0x0</span><span>' + fmtHex(scaleSize) + '</span></div>';
            html += '</div>';

            html += '<div class="frame-table-wrap"><div class="frame-table">';
            html += '<div class="frame-table-head"><div>Member</div><div>Offset</div><div>Size</div><div>Type / Notes</div></div>';

            members.forEach((mem, i) => {
                const offText = (mem.offset === null || mem.offset === undefined) ? '-' : fmtHex(mem.offset);
                const sizeText = (mem.nbytes === null || mem.nbytes === undefined) ? '-' : fmtHex(mem.nbytes);
                const memberName = mem.name ? esc(mem.name) : 'unnamed';

                let typeHtml = '<span class="frame-missing">no decoded type</span>';
                if (mem.tinfo && mem.tinfo.declaration) {
                    typeHtml = compactTypeHtmlFromText(mem.tinfo.declaration, false);
                }

                const chips = [];
                if (mem.has_info) chips.push('<span class="frame-chip">opinfo</span>');
                if (mem.tinfo && mem.tinfo.decode_error) chips.push('<span class="frame-chip warn">decode issue</span>');

                let notes = '';
                if (chips.length > 0) {
                    notes += '<div class="frame-member-meta">' + chips.join('') + '</div>';
                }
                if (mem.tinfo && mem.tinfo.decode_error) {
                    notes += '<div class="frame-note warn">decode: ' + esc(mem.tinfo.decode_error) + '</div>';
                }
                if (mem.cmt) {
                    notes += '<div class="frame-note">cmt: ' + esc(mem.cmt) + '</div>';
                }
                if (mem.rptcmt) {
                    notes += '<div class="frame-note">rpt: ' + esc(mem.rptcmt) + '</div>';
                }

                html += '<div class="frame-table-row">';
                html += '<div><span class="frame-member-slot">#' + i + '</span><span class="frame-member-name">' + memberName + '</span></div>';
                html += '<div class="frame-num">' + offText + '</div>';
                html += '<div class="frame-num">' + sizeText + '</div>';
                html += '<div><div class="frame-member-type">' + typeHtml + '</div>' + notes + '</div>';
                html += '</div>';
            });

            html += '</div></div>';
            html += '</div>';
            return html;
        }

        function renderSemanticTextList(items, emptyLabel) {
            const values = Array.isArray(items) ? items.filter(Boolean) : [];
            if (!values.length) {
                return '<div class="metadata-empty">' + esc(emptyLabel) + '</div>';
            }
            return '<div class="metadata-list">'
                + values.map(value => '<div class="metadata-item"><div class="info" style="white-space: pre-wrap;">' + esc(String(value)) + '</div></div>').join('')
                + '</div>';
        }

        function renderOpaqueBlobDetail(title, blob) {
            if (!blob) return '';
            const texts = Array.isArray(blob.printable_texts) ? blob.printable_texts : [];
            let html = '<div class="detail-section"><div class="detail-label">' + esc(title) + '</div>';
            html += '<div class="detail-grid" style="margin-bottom: var(--space-sm);">';
            html += '<div class="detail-stat"><div class="label">Raw Size</div><div class="value">' + fmtBytes(blob.size || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Fragments</div><div class="value">' + esc(String(texts.length)) + '</div></div>';
            html += '</div>';
            html += renderSemanticTextList(texts, 'No printable fragments');
            html += '</div>';
            return html;
        }

        function renderRawChunkCatalog(chunks) {
            const list = Array.isArray(chunks) ? chunks : [];
            if (!list.length) {
                return '<div class="metadata-empty">No raw metadata chunks preserved</div>';
            }
            return '<div class="metadata-list">'
                + list.map(chunk => {
                    const keyName = chunk && chunk.key_name ? String(chunk.key_name) : ('MDK_' + String(chunk && chunk.raw_key !== undefined ? chunk.raw_key : '?'));
                    const rawKey = chunk && chunk.raw_key !== undefined ? String(chunk.raw_key) : '?';
                    const size = fmtBytes(chunk && chunk.size ? chunk.size : 0);
                    const previewTexts = Array.isArray(chunk && chunk.printable_texts) ? chunk.printable_texts : [];
                    const preview = previewTexts.length ? previewTexts.join(' | ') : 'no printable preview';
                    return '<div class="metadata-item"><div><div class="name">'
                        + esc(keyName) + ' · key ' + esc(rawKey) + ' · ' + esc(size)
                        + '</div><div class="info" style="white-space: pre-wrap;">'
                        + esc(preview)
                        + '</div></div></div>';
                }).join('')
                + '</div>';
        }

        function renderSemanticMetadata(metadata) {
            const m = metadata || {};
            const extraCmts = Array.isArray(m.extra_cmts) ? m.extra_cmts : [];
            const rawChunks = Array.isArray(m.raw_chunks) ? m.raw_chunks : [];
            const rawChunkCount = Number.isFinite(Number(m.raw_chunk_count)) ? Number(m.raw_chunk_count) : rawChunks.length;
            const hasSemantic = rawChunkCount > 0 || extraCmts.length > 0 || !!m.user_stkpnts || !!m.ops || !!m.ops_ex;
            if (!hasSemantic) return '';

            let html = '<div class="metadata-section detail-anchor" id="section-semantic"><div class="metadata-header"><span>Semantic Metadata</span><span class="badge nominal">' + esc(String(rawChunkCount)) + ' CHUNKS</span></div><div class="metadata-content" style="display:flex; flex-direction:column; gap: var(--space-md);">';
            html += '<div class="detail-grid">';
            html += '<div class="detail-stat"><div class="label">Raw Chunks</div><div class="value">' + esc(String(rawChunkCount)) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Extra Comments</div><div class="value">' + esc(String(extraCmts.length)) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Stack Points</div><div class="value">' + (m.user_stkpnts ? 'PRESENT' : 'NONE') + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Operand Blobs</div><div class="value">' + esc(String((m.ops ? 1 : 0) + (m.ops_ex ? 1 : 0))) + '</div></div>';
            html += '</div>';

            if (extraCmts.length > 0) {
                html += '<div class="detail-section"><div class="detail-label">Extra Comments</div>' + renderSemanticTextList(extraCmts, 'No extra comments') + '</div>';
            }
            if (m.user_stkpnts) {
                html += renderOpaqueBlobDetail('User Stack Points', m.user_stkpnts);
            }
            if (m.ops) {
                html += renderOpaqueBlobDetail('Operand Renderings', m.ops);
            }
            if (m.ops_ex) {
                html += renderOpaqueBlobDetail('Extended Operand Renderings', m.ops_ex);
            }

            html += '<div class="detail-section"><div class="detail-label">Raw Chunk Catalog</div>' + renderRawChunkCatalog(rawChunks) + '</div>';
            html += '</div></div>';
            return html;
        }

        function renderSemanticNeighborSection() {
            const currentSig = semanticNeighborRequestSig(currentDetailKeyHex);
            const loading = currentSemanticNeighborLoadingSig === currentSig;
            const ready = currentSemanticNeighborLoadedSig === currentSig;
            const error = ready ? currentSemanticNeighborError : null;
            const results = ready && Array.isArray(currentSemanticNeighbors) ? currentSemanticNeighbors : [];

            let html = '<div class="metadata-section detail-anchor" id="section-neighbors"><div class="metadata-header"><span>Semantic Neighbors</span><span class="badge nominal">';
            if (loading) html += 'LOADING';
            else if (error) html += 'ERROR';
            else html += esc(String(results.length));
            html += '</span></div><div class="metadata-content">';
            html += '<div class="binary-graph-toolbar">';
            html += '<label class="binary-graph-field"><span class="detail-label">Limit</span><input class="comment-search" type="number" min="1" max="24" value="' + esc(String(currentSemanticNeighborLimit)) + '" onchange="setSemanticNeighborLimit(this.value)"></label>';
            html += '<div class="binary-graph-field"><span class="detail-label">Strict Family</span>';
            html += '<button type="button" class="neighbor-toggle' + (currentSemanticNeighborStrictFamily ? ' active' : '') + '" onclick="toggleSemanticNeighborStrictFamily()">';
            html += '<span class="neighbor-toggle-track"><span class="neighbor-toggle-thumb"></span></span>';
            html += '<span class="neighbor-toggle-copy"><span>' + (currentSemanticNeighborStrictFamily ? 'Enabled' : 'Disabled') + '</span><span class="secondary">Family Locked</span></span>';
            html += '</button></div>';
            html += '<div class="binary-graph-hint">Suggestions only. Strict family keeps only direct or related family matches.</div>';
            html += '</div>';

            if (loading && !ready) {
                html += '<div class="metadata-empty">Loading semantic neighbors...</div>';
            } else if (error) {
                html += '<div class="metadata-empty">' + esc(error) + '</div>';
            } else if (!results.length) {
                html += '<div class="metadata-empty">No semantic neighbors found</div>';
            } else {
                html += '<div class="neighbor-results">';
                results.forEach(hit => {
                    const displayName = renderCompactSignatureText(hit.func_name_demangled || hit.func_name, false);
                    const binSummary = Array.isArray(hit.binary_names) && hit.binary_names.length
                        ? hit.binary_names.slice(0, 4).join(', ') + (hit.binary_names.length > 4 ? ' ...' : '')
                        : 'no binary aliases';
                    const href = functionDetailHref(hit.key_hex, 'section-overview');
                    const rationale = hit.semantic_neighbor || {};
                    const pills = [];
                    pills.push('<span class="neighbor-pill accent">SIM ' + esc((Number(hit.score || 0)).toFixed(3)) + '</span>');
                    if (Number(rationale.direct_binary_score || 0) > 0) pills.push('<span class="neighbor-pill accent">Direct Family</span>');
                    else if (Number(rationale.related_binary_score || 0) > 0) pills.push('<span class="neighbor-pill info">Related Family</span>');
                    if (rationale.language_match) pills.push('<span class="neighbor-pill info">Lang Match</span>');
                    if (Number(rationale.origin_overlap || 0) > 0.18) pills.push('<span class="neighbor-pill warn">Origin Overlap</span>');

                    html += '<article class="neighbor-card">';
                    html += '<div class="neighbor-card-header">';
                    html += '<div class="neighbor-card-main clickable">';
                    html += '<a class="neighbor-card-link" href="' + esc(href) + '" onclick="event.preventDefault();showFunctionDetail(\'' + esc(hit.key_hex) + '\', \"section-neighbors\")">';
                    html += '<div class="neighbor-card-title">' + displayName + '</div>';
                    html += '<div class="neighbor-card-meta"><span>' + esc(fmtRelativeTs(hit.ts)) + '</span><span>' + esc(binSummary) + '</span></div>';
                    html += '<div class="neighbor-card-key">KEY ' + esc(hit.key_hex) + '</div>';
                    html += '</a>';
                    html += '</div>';
                    html += '<div class="neighbor-card-actions"><div class="neighbor-pill-row">' + pills.join('') + '</div></div>';
                    html += '</div>';
                    html += renderSemanticNeighborRationale(rationale);
                    html += '</article>';
                });
                html += '</div>';
            }

            html += '</div></div>';
            return html;
        }

        function renderNeighborTokenRow(label, tokens) {
            const values = Array.isArray(tokens) ? tokens.filter(Boolean) : [];
            if (!values.length) return '';
            return '<div class="detail-section"><div class="detail-label">' + esc(label) + '</div><div class="result-bins">'
                + values.map(token => '<span class="bin-tag">' + esc(token) + '</span>').join('')
                + '</div></div>';
        }

        function renderNeighborBinaryRow(label, bins) {
            const values = Array.isArray(bins) ? bins.filter(Boolean) : [];
            if (!values.length) return '';
            return '<div class="detail-section"><div class="detail-label">' + esc(label) + '</div><div class="result-bins">'
                + values.map(bin => '<span class="bin-tag">' + esc(bin.basename || bin.short_id || 'binary') + '<span class="accent">#' + esc(bin.short_id || '') + '</span></span>').join('')
                + '</div></div>';
        }

        function renderSemanticNeighborRationale(rationale) {
            const r = rationale || {};
            const hasEvidence = Number(r.family_score || 0) > 0
                || Number(r.semantic_overlap || 0) > 0
                || Number(r.prototype_overlap || 0) > 0
                || Number(r.frame_overlap || 0) > 0
                || Number(r.comment_overlap || 0) > 0
                || Number(r.operand_overlap || 0) > 0
                || (Array.isArray(r.shared_semantic_tokens) && r.shared_semantic_tokens.length > 0);
            if (!hasEvidence) return '';

            const summaryParts = ['Why this matched'];
            if (Number(r.family_score || 0) > 0) summaryParts.push('family ' + Number(r.family_score || 0).toFixed(2));
            if (Number(r.semantic_overlap || 0) > 0) summaryParts.push('semantic ' + Number(r.semantic_overlap || 0).toFixed(2));
            if (r.language_match) summaryParts.push('lang match');

            const metrics = [
                ['Semantic', r.semantic_overlap],
                ['Prototype', r.prototype_overlap],
                ['Frame', r.frame_overlap],
                ['Comments', r.comment_overlap],
                ['Operands', r.operand_overlap],
                ['Family', r.family_score],
                ['Consistency', r.candidate_consistency],
                ['Lexical', r.lexical_prior],
            ].filter(entry => Number(entry[1] || 0) > 0 || entry[0] === 'Family' || entry[0] === 'Consistency');

            let html = '<details class="neighbor-rationale" onclick="event.stopPropagation()">';
            html += '<summary><span class="neighbor-rationale-title">' + esc(summaryParts.join(' · ')) + '</span></summary>';
            html += '<div class="neighbor-rationale-content">';
            html += '<div class="neighbor-rationale-grid">';
            metrics.forEach(entry => {
                html += '<div class="neighbor-metric"><div class="label">' + esc(entry[0]) + '</div><div class="value">' + esc((Number(entry[1] || 0)).toFixed(3)) + '</div></div>';
            });
            html += '</div>';

            const badges = [];
            if (r.language_match) badges.push('LANG MATCH');
            if (Number(r.direct_binary_score || 0) > 0) badges.push('DIRECT FAMILY');
            else if (Number(r.related_binary_score || 0) > 0) badges.push('RELATED FAMILY');
            if (Number(r.origin_overlap || 0) > 0.15) badges.push('ORIGIN OVERLAP');
            if (Number(r.binary_name_overlap || 0) > 0.15) badges.push('BINARY OVERLAP');
            if (badges.length) {
                html += '<div class="result-bins">' + badges.map(b => '<span class="bin-tag">' + esc(b) + '</span>').join('') + '</div>';
            }

            html += renderNeighborBinaryRow('Direct Family Binaries', r.direct_family_binaries);
            html += renderNeighborBinaryRow('Related Family Binaries', r.related_family_binaries);
            html += renderNeighborTokenRow('Distinctive Semantic Tokens', r.shared_semantic_tokens);
            html += renderNeighborTokenRow('Distinctive Prototype Tokens', r.shared_prototype_tokens);
            html += renderNeighborTokenRow('Distinctive Frame Tokens', r.shared_frame_tokens);
            html += renderNeighborTokenRow('Distinctive Comment Tokens', r.shared_comment_tokens);
            html += renderNeighborTokenRow('Distinctive Operand Tokens', r.shared_operand_tokens);
            html += '</div></details>';
            return html;
        }

        function splitTopLevelComma(text) {
            const parts = [];
            let cur = '';
            let paren = 0;
            let square = 0;
            let angle = 0;
            let brace = 0;

            for (let i = 0; i < text.length; i++) {
                const ch = text[i];

                if (ch === '(') paren++;
                else if (ch === ')' && paren > 0) paren--;
                else if (ch === '[') square++;
                else if (ch === ']' && square > 0) square--;
                else if (ch === '<') angle++;
                else if (ch === '>' && angle > 0) angle--;
                else if (ch === '{') brace++;
                else if (ch === '}' && brace > 0) brace--;

                if (ch === ',' && paren === 0 && square === 0 && angle === 0 && brace === 0) {
                    if (cur.trim()) parts.push(cur.trim());
                    cur = '';
                    continue;
                }
                cur += ch;
            }

            if (cur.trim()) parts.push(cur.trim());
            return parts;
        }

        function parseDecodedSignature(declaration) {
            const decl = (declaration || '').trim();
            if (!decl) return null;

            const close = decl.lastIndexOf(')');
            if (close <= 0) return null;

            let depth = 0;
            let open = -1;
            for (let i = close; i >= 0; i--) {
                const ch = decl[i];
                if (ch === ')') depth++;
                else if (ch === '(') {
                    depth--;
                    if (depth === 0) {
                        open = i;
                        break;
                    }
                }
            }
            if (open < 0) return null;

            const rawHead = decl.slice(0, open).trim();
            const argsBlock = decl.slice(open + 1, close).trim();
            const accessMatch = rawHead.match(/^(public|private|protected):\s*/i);
            const access = accessMatch ? accessMatch[1].toLowerCase() : null;
            const head = rawHead.replace(/^(?:public|private|protected):\s*/i, '').trim();
            if (!head || head.includes('(*')) {
                return null;
            }

            const ccPattern = /__(?:cdecl|stdcall|pascal|fastcall|thiscall|swiftcall|golang|usercall|userpurge|cc\([^)]*\))/;
            let cc = null;
            const headWithoutCc = head.replace(ccPattern, match => {
                if (!cc) cc = match;
                return ' ';
            }).replace(/\s+/g, ' ').trim();
            const parts = splitSignatureHead(headWithoutCc);
            let returnType = (parts.returnType || '').trim();
            let callableName = (parts.callable || '').trim();
            const retLocMatch = callableName.match(/@<[^>]+>/);
            const retLoc = retLocMatch ? retLocMatch[0] : null;
            callableName = callableName.replace(/\s*@<[^>]+>/g, '').trim();
            if (!returnType && !callableName) returnType = headWithoutCc || head;

            let args = [];
            if (argsBlock.length > 0) {
                args = splitTopLevelComma(argsBlock);
                if (args.length === 1 && args[0] === 'void') {
                    args = [];
                }
            }

            return {
                access,
                returnType,
                cc,
                retLoc,
                callableName: callableName || null,
                args,
                full: decl,
            };
        }


        function isAllocatorTypeLabel(label) {
            return /(^|::)allocator$/.test(String(label || '').trim());
        }

        function typeExplorerPalette(depth) {
            const palette = ['#28e0a5', '#4bb4ff', '#d6ac45', '#ff7b54', '#b57aff', '#59d1d8', '#f08bb4', '#93b85c'];
            return palette[depth % palette.length];
        }

        function normalizeTypeNode(node, showAllocators) {
            if (!node) return null;
            const label = String(node.label || '').trim();
            let args = (node.args || []).map(child => normalizeTypeNode(child, showAllocators)).filter(Boolean);
            const elided = [];

            if (!showAllocators && isAllocatorTypeLabel(label)) {
                if (args.length === 1) return args[0];
                return null;
            }

            const canonical = label.replace(/std::__1::/g, 'std::');
            if (!showAllocators) {
                if (/^std::(?:vector|list|deque|forward_list|set|multiset)$/.test(canonical) && args.length >= 2 && isAllocatorTypeLabel(args[1].label)) {
                    args = [args[0]];
                    elided.push('allocator');
                } else if (/^std::(?:map|multimap|unordered_map|unordered_multimap)$/.test(canonical)) {
                    args.forEach(child => {
                        const childLabel = String(child.label || '').trim();
                        if (isAllocatorTypeLabel(childLabel)) elided.push('allocator');
                        else if (/(^|::)less$/.test(childLabel)) elided.push('less');
                        else if (/(^|::)equal_to$/.test(childLabel)) elided.push('equal_to');
                        else if (/(^|::)hash$/.test(childLabel)) elided.push('hash');
                    });
                    args = args.filter(child => !isAllocatorTypeLabel(child.label) && !/(^|::)(less|equal_to|hash)$/.test(String(child.label || '').trim()));
                } else if (/^std::basic_string$/.test(canonical)) {
                    args.forEach((child, index) => {
                        const childLabel = String(child.label || '').trim();
                        if (index > 0 && /(^|::)char_traits$/.test(childLabel)) elided.push('char_traits');
                        else if (index > 0 && isAllocatorTypeLabel(childLabel)) elided.push('allocator');
                    });
                    args = args.filter((child, index) => index === 0 || (!/(^|::)char_traits$/.test(String(child.label || '').trim()) && !isAllocatorTypeLabel(child.label)));
                }
            }

            return { label: canonical, args, elided };
        }

        function stripTypeNoise(text) {
            return String(text || '').replace(/\b(class|struct|enum)\s+/g, '').replace(/std::__1::/g, 'std::').trim();
        }

        function splitTypeLabelParts(label) {
            const cleaned = stripTypeNoise(label);
            const parts = cleaned.split(/\s+/).filter(Boolean);
            if (!parts.length) return { prefix: '', name: 'unknown' };
            const name = parts.pop() || 'unknown';
            return { prefix: parts.join(' '), name };
        }

        function typeExplorerLabel(label) {
            const parts = splitTypeLabelParts(label);
            return String(parts.name || '').replace(/^std::/, '').replace(/^.*::/, '').trim() || 'unknown';
        }

        function typeExplorerPath(label) {
            const value = String(label || '').replace(/std::__1::/g, 'std::').trim();
            const parts = splitScope(value);
            return parts.length > 1 ? parts.slice(0, -1).join('::') : '';
        }

        function flattenTypeTree(node, depth = 0, branch = 0, rows = []) {
            if (!node) return rows;
            rows.push({ label: node.label, depth, branch, childCount: node.args.length, path: typeExplorerPath(node.label) });
            node.args.forEach((child, index) => flattenTypeTree(child, depth + 1, index, rows));
            return rows;
        }

        function countTypeTreeNodes(node) {
            if (!node) return 0;
            return 1 + (node.args || []).reduce((sum, child) => sum + countTypeTreeNodes(child), 0);
        }

        function maxTypeTreeDepth(node) {
            if (!node) return 0;
            if (!node.args || !node.args.length) return 0;
            return 1 + Math.max(...node.args.map(maxTypeTreeDepth));
        }

        function typeToCompactString(node) {
            if (!node) return '';
            const parts = splitTypeLabelParts(node.label);
            const base = typeExplorerLabel(parts.name);
            const prefix = parts.prefix ? parts.prefix + ' ' : '';
            if (!node.args || !node.args.length) return prefix + base;
            return prefix + base + '<' + node.args.map(typeToCompactString).join(', ') + '>';
        }

        function buildTypeExplorerNode(text, showAllocators) {
            const cleaned = stripTypeNoise(text);
            if (!cleaned) return null;
            if (cleaned === '...') return { label: '...', args: [], displayLabel: '...', pathLabel: '', elided: [] };
            const open = cleaned.indexOf('<');
            if (open < 0) return { label: cleaned, args: [], displayLabel: cleaned, pathLabel: '', elided: [] };
            const close = findMatchingAngle(cleaned, open);
            if (close < 0) return { label: cleaned, args: [], displayLabel: cleaned, pathLabel: '', elided: [] };
            const templateText = cleaned.slice(0, close + 1);
            const suffix = cleaned.slice(close + 1).trim();
            const node = normalizeTypeNode(parseTemplateNode(templateText), showAllocators);
            if (!node) return null;
            if (suffix) node.displaySuffix = suffix;
            return node;
        }

        function decorateTypeExplorerNode(node, extras = {}) {
            if (!node) return null;
            return Object.assign({}, node, extras, {
                args: (node.args || []).map(child => decorateTypeExplorerNode(child))
            });
        }

        function buildSignatureExplorerTree(parsed, showAllocators) {
            if (!parsed) return [];
            const argumentChildren = [];
            (parsed.args || []).forEach((arg, index) => {
                const parts = splitArgumentName(arg);
                const argNode = decorateTypeExplorerNode(buildTypeExplorerNode(parts.typeText || arg, showAllocators), {
                    note: '',
                    displayLabel: stripTypeNoise(parts.typeText || arg) || ('arg ' + index)
                });
                if (argNode) argumentChildren.push(argNode);
            });
            return [
                {
                    label: 'argument-list',
                    displayLabel: 'Arguments',
                    note: parsed.cc || '',
                    pathLabel: '',
                    args: argumentChildren,
                    elided: []
                },
                {
                    label: 'return-type',
                    displayLabel: 'Return Type',
                    note: '',
                    pathLabel: '',
                    args: [decorateTypeExplorerNode(buildTypeExplorerNode(parsed.returnType || 'void', showAllocators), {
                        note: '',
                        displayLabel: stripTypeNoise(parsed.returnType || 'void') || 'void',
                        pathLabel: parsed.retLoc || ''
                    })].filter(Boolean),
                    elided: []
                }
            ];
        }

        function countTypeTreeNodesDeep(nodes) {
            return (nodes || []).reduce((sum, node) => sum + countTypeTreeNodes(node), 0);
        }

        function maxTypeTreeDepthDeep(nodes) {
            return (nodes || []).reduce((max, node) => Math.max(max, maxTypeTreeDepth(node)), 0);
        }

        function splitArgumentName(text) {
            const value = stripTypeNoise(text);
            if (!value || value === '...') return { typeText: value, argName: '' };
            let angle = 0;
            let paren = 0;
            let bracket = 0;
            for (let i = value.length - 1; i >= 0; i--) {
                const ch = value[i];
                if (ch === '>') angle += 1;
                else if (ch === '<') angle = Math.max(0, angle - 1);
                else if (ch === ')') paren += 1;
                else if (ch === '(') paren = Math.max(0, paren - 1);
                else if (ch === ']') bracket += 1;
                else if (ch === '[') bracket = Math.max(0, bracket - 1);
                else if (ch === ' ' && angle === 0 && paren === 0 && bracket === 0) {
                    const suffix = value.slice(i + 1).trim();
                    if (/^[*&]+[_A-Za-z][_A-Za-z0-9]*$/.test(suffix) || /^[_A-Za-z][_A-Za-z0-9]*$/.test(suffix)) {
                        const sigil = (suffix.match(/^[*&]+/) || [''])[0];
                        return {
                            typeText: (value.slice(0, i).trim() + (sigil ? ' ' + sigil : '')).trim(),
                            argName: suffix.slice(sigil.length)
                        };
                    }
                    break;
                }
            }
            return { typeText: value, argName: '' };
        }

        function stripTopLevelTemplateSuffix(text) {
            const value = String(text || '').trim();
            const open = value.indexOf('<');
            if (open < 0) return value;
            const close = findMatchingAngle(value, open);
            if (close === value.length - 1) return value.slice(0, open).trim();
            return value;
        }

        function renderCallableNameHtml(rawName, showAllocators) {
            const value = String(rawName || '').trim();
            if (!value) return '';
            const lastScope = findLastTopLevelScope(value);
            const leafRaw = lastScope >= 0 ? value.slice(lastScope + 2).trim() : value;
            const scopeRaw = lastScope >= 0 ? value.slice(0, lastScope).trim() : '';
            let leafDisplay = stripTopLevelTemplateSuffix(leafRaw);
            if (!/^operator\S+$/.test(leafDisplay)) leafDisplay = typeExplorerLabel(leafDisplay);
            const scopeHtml = scopeRaw ? compactTypeHtmlFromText(scopeRaw, showAllocators) + "<span class='type-compact-token punct'>::</span>" : '';
            return " <span class='type-explorer-func-scope'>" + scopeHtml + "</span><span class='type-explorer-func-name'>" + esc(leafDisplay || leafRaw) + "</span>";
        }

        function compactTypeHtmlFromText(text, showAllocators) {
            const cleaned = stripTypeNoise(text);
            if (!cleaned) return '<span class="type-explorer-generic">unknown</span>';
            if (cleaned === '...') return '<span class="type-explorer-generic">...</span>';
            const open = cleaned.indexOf('<');
            if (open < 0) return '<span class="type-explorer-generic">' + esc(cleaned) + '</span>';
            const close = findMatchingAngle(cleaned, open);
            if (close < 0) return '<span class="type-explorer-generic">' + esc(cleaned) + '</span>';
            const templateText = cleaned.slice(0, close + 1);
            const suffix = cleaned.slice(close + 1).trim();
            const node = normalizeTypeNode(parseTemplateNode(templateText), showAllocators);
            if (!node) return '<span class="type-explorer-generic">' + esc(cleaned) + '</span>';
            return renderCompactType(node) + (suffix ? '<span class="type-compact-token punct">' + esc(suffix) + '</span>' : '');
        }

        function buildCompactDeclarationHtml(parsed, showAllocators) {
            const accessHtml = parsed.access ? "<span class='type-explorer-cc'>" + esc(parsed.access + ':') + "</span> " : '';
            const returnHtml = !parsed.returnType && parsed.callableName
                ? ''
                : parsed.returnType && /[<(]/.test(parsed.returnType)
                ? compactTypeHtmlFromText(parsed.returnType, showAllocators)
                : "<span class='type-explorer-return'>" + esc(parsed.returnType || 'void') + "</span>";
            const args = (parsed.args || []).map(arg => {
                const parts = splitArgumentName(arg);
                const typeHtml = compactTypeHtmlFromText(parts.typeText || arg, showAllocators);
                const nameHtml = parts.argName ? '<span class="type-explorer-arg-name"> ' + esc(parts.argName) + '</span>' : '';
                return typeHtml + nameHtml;
            }).join('<span class="type-compact-token punct">, </span>');
            const callableName = parsed.callableName ? renderCallableNameHtml(parsed.callableName, showAllocators) : '';
            const ccHtml = parsed.cc ? " <span class='type-explorer-cc'>" + esc(parsed.cc) + "</span>" : '';
            return accessHtml + returnHtml + ccHtml + callableName + "(" + args + ")";
        }

        function renderQualifiedCallableSuffix(text) {
            const value = String(text || '').trim();
            if (!value || /[\s(),]/.test(value)) return null;
            if (findLastTopLevelScope(value) < 0) return null;
            return renderCallableNameHtml(value, false).trim();
        }

        function normalizeSymbolDisplay(text) {
            let value = String(text || '').trim();
            if (!value) return value;
            value = value
                .replace(/\$LT\$/g, '<')
                .replace(/\$GT\$/g, '>')
                .replace(/\$LP\$/g, '(')
                .replace(/\$RP\$/g, ')')
                .replace(/\$C\$/g, ',')
                .replace(/\$u20\$/g, ' ')
                .replace(/\$u5b\$/g, '[')
                .replace(/\$u5d\$/g, ']')
                .replace(/\$u7b\$/g, '{')
                .replace(/\$u7d\$/g, '}')
                .replace(/\$u27\$/g, "'")
                .replace(/\$u3d\$/g, '=')
                .replace(/\$u3a\$/g, ':')
                .replace(/\$u2b\$/g, '+')
                .replace(/\$u21\$/g, '!')
                .replace(/\$u26\$/g, '&')
                .replace(/\$u2f\$/g, '/')
                .replace(/\$u5c\$/g, '\\')
                .replace(/\.\./g, '::')
                .replace(/::h[0-9a-f]{8,}$/i, '');
            value = value.replace(/^_ZN\d+_?/, '').replace(/E$/, '');
            return value.trim();
        }

        function renderCompactSignatureText(text, showAllocators = false) {
            const value = normalizeSymbolDisplay(stripTypeNoise(text));
            if (!value) return '';
            const parsed = parseDecodedSignature(value);
            if (parsed) return buildCompactDeclarationHtml(parsed, showAllocators);
            const qualifiedCallable = renderQualifiedCallableSuffix(value);
            if (qualifiedCallable) return qualifiedCallable;
            const typeHtml = compactTypeHtmlFromText(value, showAllocators);
            if (typeHtml && !/unknown/.test(typeHtml)) return typeHtml;
            if (/^[?@_$A-Za-z][^\s]*$/.test(value)) return '<span class="result-mangled">' + esc(value) + '</span>';
            return esc(value);
        }

        function renderOverviewFunctionName(data, metadata) {
            const demangled = data && data.name ? String(data.name) : '';
            const typeDecl = metadata && metadata.type_parts && metadata.type_parts.declaration ? String(metadata.type_parts.declaration) : '';
            const parsedTypeDecl = typeDecl ? parseDecodedSignature(typeDecl) : null;
            if (parsedTypeDecl) return buildCompactDeclarationHtml(parsedTypeDecl, false);
            const parsedDemangled = demangled ? parseDecodedSignature(normalizeSymbolDisplay(stripTypeNoise(demangled))) : null;
            if (parsedDemangled && parsedDemangled.callableName) return buildCompactDeclarationHtml(parsedDemangled, false);
            if (demangled && demangled.indexOf('(') < 0) return renderCompactSignatureText(demangled, false);
            return esc(demangled || typeDecl || '-');
        }

        function tokenizeCompactType(text) {
            const tokens = [];
            let depth = 0;
            let buf = '';
            for (let i = 0; i < text.length; i++) {
                const ch = text[i];
                if (ch === '<') {
                    if (buf) tokens.push({ type: 'name', value: buf, depth });
                    buf = '';
                    tokens.push({ type: 'open', value: '<', depth });
                    depth += 1;
                } else if (ch === '>') {
                    if (buf) tokens.push({ type: 'name', value: buf, depth });
                    buf = '';
                    depth = Math.max(0, depth - 1);
                    tokens.push({ type: 'close', value: '>', depth });
                } else if (ch === ',') {
                    if (buf) tokens.push({ type: 'name', value: buf, depth });
                    buf = '';
                    tokens.push({ type: 'comma', value: ', ', depth });
                } else {
                    buf += ch;
                }
            }
            if (buf) tokens.push({ type: 'name', value: buf, depth });
            return tokens;
        }

        function renderCompactType(node) {
            if (!node) return '<span class="type-explorer-generic">unknown</span>';
            const tokens = tokenizeCompactType(typeToCompactString(node));
            return tokens.map(tok => {
                const color = tok.type === 'name' ? typeExplorerPalette(tok.depth) : (tok.type === 'comma' ? '#5e6572' : typeExplorerPalette(tok.depth));
                const klass = tok.type === 'name' ? 'name' : 'punct';
                return '<span class="type-compact-token ' + klass + '" style="color:' + color + '">' + esc(tok.value) + '</span>';
            }).join('');
        }

        function explorerNodeLabel(node) {
            return node && node.displayLabel ? node.displayLabel : typeExplorerLabel(node ? node.label : '');
        }

        function explorerNodePath(node) {
            if (!node) return '';
            if (node.pathLabel) return node.pathLabel;
            return typeExplorerPath(node.label);
        }

        function explorerNodeDepthMeta(depth, branchIndex) {
            if (branchIndex === null && depth === 0) return '';
            return branchIndex === null ? '<span class="type-layer-kicker">D' + depth + '</span>' : '<span class="type-layer-index">' + branchIndex + '</span><span class="type-layer-kicker">D' + depth + '</span>';
        }

        function renderTypeExplorerLayered(node, depth = 0, branchIndex = null, path = 'root') {
            if (!node) return '<div class="metadata-empty">No template structure detected</div>';
            const color = typeExplorerPalette(depth);
            const shortLabel = explorerNodeLabel(node);
            const scopePath = explorerNodePath(node);
            const hasChildren = !!(node.args && node.args.length);
            const chips = [];
            if ((node.elided || []).length) chips.push('<span class="type-layer-chip">-' + esc(node.elided.join(', ')) + '</span>');
            if (node.displaySuffix) chips.push('<span class="type-layer-chip">' + esc(node.displaySuffix) + '</span>');
            if (node.note) chips.push('<span class="type-layer-chip">' + esc(node.note) + '</span>');
            const toggle = hasChildren ? '<button class="type-layer-toggle" onclick="toggleTypeTree(event, \'' + path + '\')">▼</button>' : '<span class="type-layer-toggle"></span>';
            const index = explorerNodeDepthMeta(depth, branchIndex);
            const children = hasChildren
                ? '<div class="type-layer-children" data-type-layer-children="' + path + '">' + node.args.map((child, index) => renderTypeExplorerLayered(child, depth + 1, index, path + '-' + index)).join('') + '</div>'
                : '';
            return '<div class="type-layer-branch" style="--layer-color:' + color + '"><div class="type-layer-node' + (hasChildren ? '' : ' leaf') + '"><span class="type-layer-pin"></span><div class="type-layer-head">'
                + toggle
                + '<span class="type-layer-label">' + esc(shortLabel) + '</span>'
                + index
                + chips.join('')
                + '</div>'
                + (scopePath ? '<div class="type-layer-path">' + esc(scopePath) + '</div>' : '')
                + (hasChildren ? '<div class="type-layer-meta"><span>&lt;</span><span>' + node.args.length + ' param' + (node.args.length === 1 ? '' : 's') + '</span></div>' : '')
                + children
                + '</div></div>';
        }

        function renderTypeExplorerLayeredForest(nodes) {
            if (!nodes || !nodes.length) return '<div class="metadata-empty">No template structure detected</div>';
            return '<div class="type-explorer-layered">' + nodes.map((node, index) => renderTypeExplorerLayered(node, 0, null, 'forest-' + index)).join('') + '</div>';
        }

        function renderTypeExplorerHorizontal(node, depth = 0, path = 'root') {
            if (!node) return '<div class="metadata-empty">No template structure detected</div>';
            const color = typeExplorerPalette(depth);
            const label = explorerNodeLabel(node);
            const hasChildren = !!(node.args && node.args.length);
            const meta = '<span class="type-horizontal-meta">D' + depth + '</span>' + ((node.elided || []).length ? '<span class="type-horizontal-meta">-' + esc(node.elided.join(', ')) + '</span>' : '') + (node.displaySuffix ? '<span class="type-horizontal-meta">' + esc(node.displaySuffix) + '</span>' : '') + (node.note ? '<span class="type-horizontal-note">' + esc(node.note) + '</span>' : '');
            if (!hasChildren) {
                return '<div class="type-horizontal-leaf" style="--layer-color:' + color + '"><div class="type-horizontal-label">' + esc(label) + '</div><div class="type-horizontal-meta">D' + depth + '</div>' + (node.note ? '<div class="type-horizontal-note">' + esc(node.note) + '</div>' : '') + '</div>';
            }
            const children = '<div class="type-horizontal-children" data-type-layer-children="' + path + '">' + node.args.map((child, index) => '<div class="type-horizontal-child">' + (index > 0 ? '<span class="type-horizontal-sep">&middot;</span>' : '') + renderTypeExplorerHorizontal(child, depth + 1, path + '-' + index) + '</div>').join('') + '</div>';
            return '<div class="type-horizontal-node" style="--layer-color:' + color + '"><div class="type-horizontal-head" onclick="toggleTypeTree(event, \'' + path + '\')"><button class="type-layer-toggle">▼</button><span class="type-horizontal-label">' + esc(label) + '</span>' + meta + '</div>' + children + '</div>';
        }

        function renderTypeExplorerHorizontalForest(nodes) {
            if (!nodes || !nodes.length) return '<div class="metadata-empty">No template structure detected</div>';
            return '<div class="type-explorer-horizontal"><div class="type-horizontal-stage"><div class="type-horizontal-root">' + nodes.map((node, index) => renderTypeExplorerHorizontal(node, 0, 'forest-' + index)).join('<div style="height:12px"></div>') + '</div></div></div>';
        }

        function setTypeExplorerMode(mode) {
            typeExplorerMode = ['layered', 'horizontal'].includes(mode) ? mode : 'layered';
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleTypeExplorerAllocators() {
            typeExplorerShowAllocators = !typeExplorerShowAllocators;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleTypeTree(event, path) {
            if (event) event.stopPropagation();
            const children = document.querySelector('[data-type-layer-children="' + path + '"]');
            if (!children) return;
            const hidden = children.style.display === 'none';
            children.style.display = hidden ? '' : 'none';
            const button = event && event.currentTarget ? event.currentTarget : null;
            const toggle = button ? button.querySelector('.type-layer-toggle') || button : null;
            if (toggle) toggle.textContent = hidden ? '▼' : '▶';
        }

        function renderTypeSignature(typeParts) {
            const decl = typeParts && typeParts.declaration ? typeParts.declaration : '';
            const parsed = parseDecodedSignature(decl);
            let html = "<div class='signature-viz'>";
            if (parsed) {
                const signatureNodes = buildSignatureExplorerTree(parsed, typeExplorerShowAllocators);
                const nodeCount = countTypeTreeNodesDeep(signatureNodes);
                const maxDepth = maxTypeTreeDepthDeep(signatureNodes);
                const compactDecl = buildCompactDeclarationHtml(parsed, typeExplorerShowAllocators);
                html += "<div class='type-explorer'>";
                html += "<div class='type-explorer-topbar'>";
                html += "<div class='type-explorer-stat'><div class='label'>User Type</div><div class='value " + (typeParts.userti ? '' : 'warn') + "'>" + (typeParts.userti ? 'YES' : 'NO') + "</div></div>";
                html += "<div class='type-explorer-stat'><div class='label'>Return Type</div><div class='value'>" + esc(parsed.returnType || '-') + "</div></div>";
                html += "<div class='type-explorer-stat'><div class='label'>Calling Conv</div><div class='value'>" + esc(parsed.cc || 'default') + "</div></div>";
                html += "<div class='type-explorer-stat'><div class='label'>Return Loc</div><div class='value'>" + esc(parsed.retLoc || '-') + "</div></div>";
                html += "</div>";
                html += "<div class='type-explorer-declaration'><div class='detail-label' style='margin:0;'>Compact Declaration</div><div class='type-explorer-decl-box'>" + compactDecl + "</div></div>";
                html += "<div class='type-explorer-togglebar'><div class='type-explorer-modes'>";
                html += "<button class='type-explorer-mode" + (typeExplorerMode === 'horizontal' ? ' active' : '') + "' onclick='setTypeExplorerMode(\"horizontal\")'>Horizontal</button>";
                html += "<button class='type-explorer-mode" + (typeExplorerMode === 'layered' ? ' active' : '') + "' onclick='setTypeExplorerMode(\"layered\")'>Layered</button>";
                html += "</div><button class='type-explorer-alloc-toggle' onclick='toggleTypeExplorerAllocators()'>" + (typeExplorerShowAllocators ? 'Hide Allocators' : 'Show Allocators') + "</button></div>";
                html += "<div class='type-explorer-canvas " + typeExplorerMode + "'>";
                if (!signatureNodes.length) html += "<div class='metadata-empty'>No template structure detected</div>";
                else if (typeExplorerMode === 'horizontal') html += renderTypeExplorerHorizontalForest(signatureNodes) + "<div class='type-explorer-legend'><span>Depth</span>" + Array.from({length: maxDepth + 1}, (_, d) => "<span class='type-explorer-legend-item'><span class='type-explorer-legend-dot' style='--dot-color:" + typeExplorerPalette(d) + "'></span>" + d + "</span>").join('') + "</div>";
                else html += renderTypeExplorerLayeredForest(signatureNodes);
                html += "</div>";
                html += "<details><summary class='type-explorer-raw'>Raw Type String</summary><div class='type-explorer-raw-block'>" + esc(parsed.full) + "</div></details>";
                html += "</div>";

                if (parsed.args.length > 0) {
                    html += "<div class='detail-label' style='margin:0;'>Arguments</div>";
                    html += "<div class='signature-args'>";
                    parsed.args.forEach((arg, i) => {
                        const kind = arg === '...' ? 'vararg' : ('arg ' + i);
                        const parts = splitArgumentName(arg);
                        html += "<div class='signature-arg-row'>";
                        html += "<div class='signature-arg-key'>" + esc(kind) + "</div>";
                        html += "<div class='signature-arg-val'>" + compactTypeHtmlFromText(parts.typeText || arg, typeExplorerShowAllocators) + (parts.argName ? "<span class='type-explorer-arg-name'> " + esc(parts.argName) + "</span>" : "") + "</div>";
                        html += "</div>";
                    });
                    html += "</div>";
                } else {
                    html += "<div class='metadata-empty'>No explicit arguments</div>";
                }
            } else {
                html += "<div class='signature-cards'>";
                html += "<div class='signature-card'><div class='label'>User Type</div><div class='value accent'>" + (typeParts.userti ? 'YES' : 'NO') + "</div></div>";
                html += "<div class='signature-card' style='grid-column: span 3;'><div class='label'>Decoded Declaration</div><div class='value'>" + esc(decl || 'not available') + "</div></div>";
                html += "</div>";
            }

            if (typeParts && typeParts.decode_error) {
                html += '<div class="detail-section" style="margin-bottom:0;"><div class="detail-label">Decode Error</div><div class="detail-value">' + esc(typeParts.decode_error) + '</div></div>';
            }

            html += '</div>';
            return html;
        }

        function renderInstructionCommentTimeline(insnCmts, rptInsnCmts, controlFlow) {
            const events = [];
            const cfCtx = buildControlFlowContext(controlFlow);
            if (Array.isArray(insnCmts)) {
                insnCmts.forEach(c => {
                    events.push({
                        kind: 'reg',
                        chunk: Number(c.fchunk_nr || 0),
                        off: Number(c.fchunk_off || 0),
                        cmt: c.cmt || '',
                    });
                });
            }
            if (Array.isArray(rptInsnCmts)) {
                rptInsnCmts.forEach(c => {
                    events.push({
                        kind: 'rpt',
                        chunk: Number(c.fchunk_nr || 0),
                        off: Number(c.fchunk_off || 0),
                        cmt: c.cmt || '',
                    });
                });
            }

            if (events.length === 0) {
                return '<div class="metadata-empty">No instruction comments</div>';
            }

            const filterKind = commentFilterKind;
            const term = commentSearchTerm.trim().toLowerCase();
            const filteredEvents = events.filter(ev => {
                ev.controlFlowRowId = cfCtx.controlFlowId(ev.kind, ev.chunk, ev.off);
                ev.controlFlowGroupId = cfCtx.rowToGroup.get(ev.controlFlowRowId) || null;
                if (filterKind !== 'all' && ev.kind !== filterKind) return false;
                if (term && !ev.cmt.toLowerCase().includes(term)) return false;
                if (controlFlowFocusMode && selectedControlFlowGroup) return ev.controlFlowGroupId === selectedControlFlowGroup;
                return true;
            });

            let html = '<div class="comment-toolbar">';
            html += '<div class="comment-filters">';
            html += '<button class="comment-filter-btn' + (filterKind === 'all' ? ' active' : '') + '" onclick="setCommentFilter(\'all\')">All</button>';
            html += '<button class="comment-filter-btn' + (filterKind === 'reg' ? ' active' : '') + '" onclick="setCommentFilter(\'reg\')">Regular</button>';
            html += '<button class="comment-filter-btn' + (filterKind === 'rpt' ? ' active' : '') + '" onclick="setCommentFilter(\'rpt\')">Repeatable</button>';
            html += '</div>';
            html += '<input class="comment-search" placeholder="Filter comment text..." value="' + esc(commentSearchTerm) + '" oninput="setCommentSearchTerm(this.value)">';
            html += '</div>';

            if (filteredEvents.length === 0) {
                html += '<div class="metadata-empty">No comments match current filters</div>';
                return html;
            }

            const byChunk = new Map();
            filteredEvents.forEach(ev => {
                if (!byChunk.has(ev.chunk)) byChunk.set(ev.chunk, []);
                byChunk.get(ev.chunk).push(ev);
            });

            const chunks = Array.from(byChunk.entries()).sort((a, b) => a[0] - b[0]);
            html += '<div class="comment-timeline">';

            chunks.forEach(([chunkId, chunkEvents]) => {
                const list = [...chunkEvents].sort((a, b) => {
                    if (a.off !== b.off) return a.off - b.off;
                    return a.kind.localeCompare(b.kind);
                });

                list.forEach((ev, i) => {
                    ev.rowId = 'cmt-' + chunkId + '-' + i;
                    ev.markerId = 'cmtm-' + chunkId + '-' + i;
                });

                const minOff = list[0].off;
                const maxOff = list[list.length - 1].off;
                const span = Math.max(1, maxOff - minOff);

                const atOffsetCount = new Map();
                let maxStack = 0;
                list.forEach(ev => {
                    const key = String(ev.off);
                    const stack = atOffsetCount.get(key) || 0;
                    ev.stack = stack;
                    atOffsetCount.set(key, stack + 1);
                    if (stack > maxStack) maxStack = stack;
                });

                const laneHeight = 24 + (maxStack * 8);
                const collapsed = collapsedCommentChunks.has(chunkId);

                html += '<div class="comment-chunk' + (collapsed ? ' collapsed' : '') + '">';
                html += '<div class="comment-chunk-head" onclick="toggleCommentChunk(' + chunkId + ')"><span>Chunk ' + chunkId + '</span><span class="count">' + list.length + ' comments</span></div>';
                html += '<div class="comment-lane" style="height:' + laneHeight + 'px;">';

                list.forEach(ev => {
                    const left = ((ev.off - minOff) / span) * 100;
                    const top = 6 + (ev.stack * 8);
                    const title = (ev.kind === 'rpt' ? 'Repeatable' : 'Regular') + ' @ ' + fmtHex(ev.off) + ': ' + ev.cmt;
                    let markerClick = 'focusCommentRow(\'' + ev.rowId + '\', \'' + ev.markerId + '\', true)';
                    if (ev.controlFlowGroupId) {
                        markerClick = 'activateCommentEvent(\'' + ev.rowId + '\', \'' + ev.markerId + '\', \'' + ev.controlFlowRowId + '\', \'' + ev.controlFlowGroupId + '\', true)';
                    }
                    html += '<div id="' + ev.markerId + '" class="comment-marker' + (ev.kind === 'rpt' ? ' repeatable' : '') + '" style="left:' + left.toFixed(2) + '%;top:' + top + 'px;" title="' + esc(title) + '" onmouseenter="pulseCommentMarker(\'' + ev.markerId + '\')" onclick="' + markerClick + '"></div>';
                });

                html += '</div>';
                html += '<div class="comment-scale"><span>' + fmtHex(minOff) + '</span><span>' + fmtHex(maxOff) + '</span></div>';

                html += '<div class="comment-list">';
                list.forEach(ev => {
                    const dimmed = selectedControlFlowGroup && ev.controlFlowGroupId !== selectedControlFlowGroup;
                    const activeCf = selectedControlFlowRow && ev.controlFlowRowId === selectedControlFlowRow;
                    let click = 'focusCommentRow(\'' + ev.rowId + '\', \'' + ev.markerId + '\', false)';
                    if (ev.controlFlowGroupId) {
                        click = 'activateCommentEvent(\'' + ev.rowId + '\', \'' + ev.markerId + '\', \'' + ev.controlFlowRowId + '\', \'' + ev.controlFlowGroupId + '\', false)';
                    }
                    html += '<div class="comment-item' + (dimmed ? ' dimmed' : '') + (activeCf ? ' active-controlflow' : '') + '" id="' + ev.rowId + '" data-controlflow-id="' + ev.controlFlowRowId + '" onmouseenter="pulseCommentMarker(\'' + ev.markerId + '\');hoverControlFlowLink(\'' + ev.controlFlowRowId + '\')" onmouseleave="clearControlFlowHover()" onclick="' + click + '">';
                    html += '<div class="comment-item-head">';
                    html += '<span class="comment-kind' + (ev.kind === 'rpt' ? ' repeatable' : '') + '">' + (ev.kind === 'rpt' ? 'RPT' : 'REG') + '</span>';
                    html += '<span>' + fmtHex(ev.off) + '</span>';
                    html += '</div>';
                    html += renderCommentText(ev);
                    html += '</div>';
                });
                html += '</div>';
                html += '</div>';
            });

            html += '</div>';
            return html;
        }

        let activeCommentRow = null;
        let activeCommentRowTimer = null;
        let activeCommentMarker = null;
        let activeCommentMarkerTimer = null;
        let currentDetailData = null;
        let currentDetailKeyHex = null;
        let currentSemanticNeighbors = null;
        let currentSemanticNeighborLoadedSig = null;
        let currentSemanticNeighborLoadingSig = null;
        let currentSemanticNeighborError = null;
        let currentSemanticNeighborLimit = 8;
        let currentSemanticNeighborStrictFamily = false;
        let currentDetailSection = null;
        let detailScrollSyncRaf = null;
        let copiedKeyHex = null;
        let copiedKeyTimer = null;
        let pendingDetailSection = null;
        let currentCompareRecords = [];
        let typeExplorerMode = 'layered';
        let typeExplorerShowAllocators = false;
        let suppressHashHandler = false;
        const metricAnimationState = new Map();

        function pulseCommentMarker(markerId) {
            if (!markerId) return;
            const marker = document.getElementById(markerId);
            if (!marker) return;

            if (activeCommentMarker && activeCommentMarker !== marker) {
                activeCommentMarker.classList.remove('active');
            }
            if (activeCommentMarkerTimer) {
                clearTimeout(activeCommentMarkerTimer);
                activeCommentMarkerTimer = null;
            }

            marker.classList.add('active');
            activeCommentMarker = marker;
            activeCommentMarkerTimer = setTimeout(() => {
                marker.classList.remove('active');
                if (activeCommentMarker === marker) {
                    activeCommentMarker = null;
                }
                activeCommentMarkerTimer = null;
            }, 1400);
        }

        function focusCommentRow(rowId, markerId = null, shouldScroll = true) {
            let row = document.getElementById(rowId);
            if (!row) {
                row = document.querySelector('[data-controlflow-id="' + rowId + '"]');
            }
            if (!row) return;

            pulseCommentMarker(markerId);

            if (shouldScroll) {
                row.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
            }

            if (activeCommentRow && activeCommentRow !== row) {
                activeCommentRow.classList.remove('active');
            }
            if (activeCommentRowTimer) {
                clearTimeout(activeCommentRowTimer);
                activeCommentRowTimer = null;
            }

            row.classList.add('active');
            activeCommentRow = row;
            activeCommentRowTimer = setTimeout(() => {
                row.classList.remove('active');
                if (activeCommentRow === row) {
                    activeCommentRow = null;
                }
                activeCommentRowTimer = null;
            }, 1700);
        }

        function setCommentFilter(kind) {
            commentFilterKind = kind;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function setCommentSearchTerm(value) {
            commentSearchTerm = value || '';
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function activateCommentEvent(rowId, markerId, controlId = null, groupId = null, shouldScroll = false) {
            if (controlId) {
                selectControlFlowRow(controlId, groupId, false);
                setTimeout(() => focusCommentRow(rowId, markerId, shouldScroll), 0);
                return;
            }
            focusCommentRow(rowId, markerId, shouldScroll);
        }

        function toggleCommentChunk(chunkId) {
            if (collapsedCommentChunks.has(chunkId)) collapsedCommentChunks.delete(chunkId);
            else collapsedCommentChunks.add(chunkId);
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleJumpTableExpand(addr) {
            if (expandedJumpTables.has(addr)) expandedJumpTables.delete(addr);
            else expandedJumpTables.add(addr);
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function clearControlFlowSelection() {
            selectedControlFlowGroup = null;
            selectedControlFlowRow = null;
            selectedControlFlowCase = null;
            controlFlowFocusMode = false;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function selectControlFlowRow(rowId, groupId = null, rerender = true) {
            const prevGroup = selectedControlFlowGroup;
            const sameRow = selectedControlFlowRow === rowId;
            const sameGroup = (groupId || null) === (selectedControlFlowGroup || null);
            if (sameRow && sameGroup) {
                selectedControlFlowRow = null;
                if (!controlFlowFocusMode) selectedControlFlowGroup = groupId || null;
            } else {
                selectedControlFlowRow = rowId;
                if (groupId) selectedControlFlowGroup = groupId;
            }
            if (groupId && prevGroup !== groupId) selectedControlFlowCase = null;
            if (controlFlowFocusMode && !selectedControlFlowGroup) controlFlowFocusMode = false;
            if (rerender && currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function setControlFlowGroup(groupId) {
            const nextGroup = selectedControlFlowGroup === groupId ? null : groupId;
            if (nextGroup !== selectedControlFlowGroup) selectedControlFlowCase = null;
            selectedControlFlowGroup = nextGroup;
            if (!selectedControlFlowGroup) {
                selectedControlFlowRow = null;
                controlFlowFocusMode = false;
            }
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function setControlFlowCase(groupId, label) {
            if (!groupId || !label) return;
            if (selectedControlFlowGroup !== groupId) {
                selectedControlFlowGroup = groupId;
            }
            selectedControlFlowCase = selectedControlFlowCase === label ? null : label;
            selectedControlFlowRow = null;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function clearControlFlowCase() {
            selectedControlFlowCase = null;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleControlFlowFocusMode() {
            if (!selectedControlFlowGroup) return;
            controlFlowFocusMode = !controlFlowFocusMode;
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function toggleSwitchGroup(groupId) {
            if (collapsedSwitchGroups.has(groupId)) collapsedSwitchGroups.delete(groupId);
            else collapsedSwitchGroups.add(groupId);
            if (currentDetailData) renderFunctionDetail(currentDetailData);
        }

        function jumpToControlFlowTable(addr) {
            const node = document.getElementById('jt-' + addr);
            if (node) node.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }

        function openAllJumpRefs(addr) {
            expandedJumpTables.add(addr);
            if (currentDetailData) {
                renderFunctionDetail(currentDetailData);
                setTimeout(() => jumpToControlFlowTable(addr), 0);
            }
        }

        function hoverControlFlowLink(controlId) {
            clearControlFlowHover();
            document.querySelectorAll('[data-controlflow-id="' + controlId + '"]').forEach(node => node.classList.add('linked'));
        }

        function clearControlFlowHover() {
            document.querySelectorAll('.linked').forEach(node => node.classList.remove('linked'));
        }

        function parseControlFlowComment(text) {
            const cmt = String(text || '').trim();
            if (cmt.startsWith('switch ')) {
                return { type: 'switch', summary: cmt, chips: [] };
            }
            if (cmt.startsWith('jumptable ')) {
                const rest = cmt.slice('jumptable '.length);
                const space = rest.indexOf(' ');
                const addr = space >= 0 ? rest.slice(0, space) : rest;
                const rel = space >= 0 ? rest.slice(space + 1).trim() : '';
                const labels = [];
                if (rel.includes('default case')) labels.push('default');
                rel.split(/[,\s]+/).forEach(tok => {
                    if (/^\d+(?:-\d+)?$/.test(tok)) labels.push(tok);
                });
                return { type: 'jumptable', addr, summary: rel || 'entry', chips: labels };
            }
            return null;
        }

        function renderCommentText(ev) {
            const parsed = parseControlFlowComment(ev.cmt);
            if (!parsed) return '<div class="comment-item-text">' + renderCompactSignatureText(ev.cmt, false) + '</div>';
            let html = '<div class="comment-item-text controlflow">';
            html += '<div class="comment-flow-main">';
            html += '<span class="frame-chip' + (parsed.type === 'jumptable' ? '' : ' warn') + '">' + esc(parsed.type) + '</span>';
            if (parsed.addr) html += '<span class="frame-chip">' + esc(parsed.addr) + '</span>';
            parsed.chips.slice(0, 12).forEach(label => {
                html += '<span class="case-chip' + (label === 'default' ? ' default' : '') + '">' + esc(label) + '</span>';
            });
            html += '</div>';
            html += '<div class="comment-flow-detail">' + esc(parsed.summary) + '</div>';
            html += '</div>';
            return html;
        }

        function parseHash() {
            const params = new URLSearchParams(window.location.hash.slice(1));
            return {
                m: params.get('m') || 'functions',
                q: params.get('q') || '',
                page: parseInt(params.get('page') || '1', 10) || 1,
                f: params.get('f') || '',
                b: params.get('b') || '',
                s: params.get('s') || '',
                fk: params.get('fk') || '',
                fb: params.get('fb') || '',
                fm: params.get('fm') || 'summary',
                fa: params.get('fa') === '1',
                bc: params.get('bc') || '',
                bcm: params.get('bcm') || 'all',
                bcp: parseInt(params.get('bcp') || '1', 10) || 1,
                bcq: params.get('bcq') || ''
            };
        }

        function updateHash(mode, query, page = 1, functionKey = '', binaryMd5 = '', sectionId = '', functionCompareKeys = '', functionCompareBaseline = '', functionCompareMode = 'summary', functionCompareShowAll = false, compareRightMd5 = '', compareMode = 'all', comparePage = 1, compareQuery = '') {
            const params = new URLSearchParams();
            if (mode && mode !== 'functions') params.set('m', mode);
            if (query) params.set('q', query);
            if (query && page > 1) params.set('page', String(page));
            if (functionKey) params.set('f', functionKey);
            if (binaryMd5) params.set('b', binaryMd5);
            if (functionKey && sectionId) params.set('s', sectionId);
            if (functionCompareKeys) params.set('fk', functionCompareKeys);
            if (functionCompareKeys && functionCompareBaseline) params.set('fb', functionCompareBaseline);
            if (functionCompareKeys && functionCompareMode && functionCompareMode !== 'summary') params.set('fm', functionCompareMode);
            if (functionCompareKeys && functionCompareShowAll) params.set('fa', '1');
            if (binaryMd5 && compareRightMd5) params.set('bc', compareRightMd5);
            if (binaryMd5 && compareRightMd5 && compareMode && compareMode !== 'all') params.set('bcm', compareMode);
            if (binaryMd5 && compareRightMd5 && comparePage > 1) params.set('bcp', String(comparePage));
            if (binaryMd5 && compareRightMd5 && compareQuery) params.set('bcq', compareQuery);
            const nextHash = params.toString();
            if (!nextHash) {
                history.replaceState(null, '', window.location.pathname);
                return;
            }
            const currentHash = window.location.hash.replace(/^#/, '');
            if (currentHash === nextHash) return;
            suppressHashHandler = true;
            window.location.hash = nextHash;
            setTimeout(() => { suppressHashHandler = false; }, 0);
        }

        function syncHashWithUi() {
            const functionCompareOpen = isDetailPageOpen() && !currentDetailKeyHex && compareKeys.length >= 2;
            const functionKey = !functionCompareOpen && isDetailPageOpen() && currentDetailKind === 'function' && currentDetailKeyHex ? currentDetailKeyHex : '';
            const functionCompareKeys = functionCompareOpen ? compareKeys.join(',') : '';
            const functionCompareBaseline = functionCompareOpen ? (compareBaselineKey || compareKeys[0] || '') : '';
            const hashMode = functionKey ? 'functions' : currentSearchMode;
            const binaryMd5 = !functionKey && !functionCompareOpen && currentSearchMode === 'binaries' && currentBinaryMd5 && ((isDetailPageOpen() && currentDetailKind === 'binary') || isComparePageOpen()) ? currentBinaryMd5 : '';
            const sectionId = functionKey ? (currentDetailSection || pendingDetailSection || '') : '';
            const compareRightMd5 = !functionKey && !functionCompareOpen && currentBinaryCompareData && currentBinaryCompareData.right && isComparePageOpen() ? currentBinaryCompareData.right.md5_hex : '';
            updateHash(hashMode, currentQuery, currentPage, functionKey, binaryMd5, sectionId, functionCompareKeys, functionCompareBaseline, compareMode, compareShowAll, compareRightMd5, currentBinaryCompareMode, currentBinaryComparePage, currentBinaryCompareQuery);
        }

        function applyHashState(state) {
            const mode = (state && state.m) ? state.m : 'functions';
            const q = (state && state.q) ? state.q : '';
            const page = state && state.page ? state.page : 1;
            const f = (state && state.f) ? state.f : '';
            const b = (state && state.b) ? state.b : '';
            const s = (state && state.s) ? state.s : null;
            const fk = (state && state.fk) ? state.fk.split(',').filter(Boolean) : [];
            const fb = (state && state.fb) ? state.fb : '';
            const fm = (state && state.fm) ? state.fm : 'summary';
            const fa = !!(state && state.fa);
            const bc = (state && state.bc) ? state.bc : '';
            const bcm = (state && state.bcm) ? state.bcm : 'all';
            const bcp = state && state.bcp ? state.bcp : 1;
            const bcq = (state && state.bcq) ? state.bcq : '';

            const effectiveMode = f ? 'functions' : mode;
            setSearchMode(effectiveMode, false, false);
            el.q.value = q;
            if (q) {
                runSearch(q, page, false).then(() => {
                    const needsOpen = f && (!isDetailPageOpen() || currentDetailKeyHex !== f || currentCompareRecords.length > 0 || currentDetailKind !== 'function');
                    if (needsOpen) showFunctionDetail(f, s, false);
                    else if (fk.length >= 2) {
                        compareKeys.length = 0;
                        fk.forEach(key => compareKeys.push(key));
                        compareBaselineKey = fb || fk[0] || null;
                        compareMode = fm === 'full' ? 'full' : 'summary';
                        compareShowAll = fa;
                        hydrateCompareItems(compareKeys);
                        openCompareModal();
                    }
                    else if (f && s && currentDetailKeyHex === f && !currentCompareRecords.length) activateDetailSection(s, false, false);
                    else if (b && (!isDetailPageOpen() || currentBinaryMd5 !== b || currentDetailKind !== 'binary')) showBinaryDetail(b, false);
                    if (b && bc) {
                        currentBinaryCompareMode = bcm;
                        currentBinaryComparePage = bcp;
                        currentBinaryCompareQuery = bcq;
                        setTimeout(() => loadBinaryCompare(bc), 0);
                    }
                    else if (!f && !b && (isDetailPageOpen() || isComparePageOpen()) && !currentCompareRecords.length) closeDetailModal(false);
                });
                return;
            }

            showDashboard(false);
            if (f && (!isDetailPageOpen() || currentDetailKeyHex !== f || currentCompareRecords.length > 0 || currentDetailKind !== 'function')) {
                showFunctionDetail(f, s, false);
            } else if (fk.length >= 2) {
                compareKeys.length = 0;
                fk.forEach(key => compareKeys.push(key));
                compareBaselineKey = fb || fk[0] || null;
                compareMode = fm === 'full' ? 'full' : 'summary';
                compareShowAll = fa;
                hydrateCompareItems(compareKeys);
                openCompareModal();
            } else if (f && s && currentDetailKeyHex === f && !currentCompareRecords.length) {
                activateDetailSection(s, false, false);
            } else if (b && (!isDetailPageOpen() || currentBinaryMd5 !== b || currentDetailKind !== 'binary')) {
                showBinaryDetail(b, false);
                if (bc) {
                    currentBinaryCompareMode = bcm;
                    currentBinaryComparePage = bcp;
                    currentBinaryCompareQuery = bcq;
                    setTimeout(() => loadBinaryCompare(bc), 0);
                }
            } else if (!f && !b && (isDetailPageOpen() || isComparePageOpen()) && !currentCompareRecords.length) {
                closeDetailModal(false);
            }
        }

        function updateTime() {
            const now = new Date();
            el.timestamp.textContent = now.toTimeString().split(' ')[0];
            el.sysTime.textContent = `${now.toISOString().split('T')[0]} ${now.toTimeString().split(' ')[0]} UTC`;
        }

        async function fetchMetrics() {
            try {
                const r = await fetch('/api/metrics');
                if (!r.ok) throw new Error(r.status);
                const d = await r.json();

                const nowMs = Date.now();
                const prev = metricsPrevSnapshot;
                const dtSec = metricsPrevTsMs > 0 ? Math.max(0.001, (nowMs - metricsPrevTsMs) / 1000) : 0;

                animateMetricValue(el.mIndexed, d.indexed_funcs || 0, fmtWholeAnimated, 1050);
                animateMetricValue(el.mStorage, d.storage_bytes || 0, fmtBytesAnimated, 1100);
                animateMetricValue(el.mSearchDocs, d.search_docs || 0, fmtWholeAnimated, 1000);
                animateMetricValue(el.mBinaries, d.unique_binaries || 0, fmtWholeAnimated, 950);
                animateMetricValue(el.mQueried, d.queried_funcs || 0, fmtWholeAnimated, 1000);
                animateMetricValue(el.mRpc, d.active_connections || 0, fmtWholeAnimated, 650);
                animateMetricValue(el.mUpstream, d.upstream_requests || 0, fmtWholeAnimated, 900);
                animateMetricValue(el.mFetched, d.upstream_fetched || 0, fmtWholeAnimated, 900);
                animateMetricValue(el.mNew, d.new_funcs || 0, fmtWholeAnimated, 850);
                animateMetricValue(el.mPulls, d.pulls || 0, fmtWholeAnimated, 850);
                animateMetricValue(el.mPushes, d.pushes || 0, fmtWholeAnimated, 850);
                animateMetricValue(el.mScoring, d.scoring_batches || 0, fmtWholeAnimated, 900);
                animateMetricValue(el.mErrors, d.errors || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mTimeouts, d.timeouts || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mRejects, d.decoder_rejects || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mAppend, d.append_failures || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mOverflow, d.index_overflows || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mUpErr, d.upstream_errors || 0, fmtWholeAnimated, 700);
                animateMetricValue(el.mTotalRec, d.total_records || 0, fmtWholeAnimated, 1100);
                animateMetricValue(el.mVconsidered, d.scoring_versions_considered || 0, fmtWholeAnimated, 1000);
                animateMetricValue(el.mFallback, d.scoring_fallback_latest || 0, fmtWholeAnimated, 900);

                animateMetricValue(el.protoV5, d.lumina_v5p || 0, fmtWholeAnimated, 650);
                animateMetricValue(el.protoV0, d.lumina_v0_4 || 0, fmtWholeAnimated, 650);

                setRateText(el.rateQps, d.queried_funcs, prev && prev.queried_funcs, dtSec);
                setRateText(el.ratePulls, d.pulls, prev && prev.pulls, dtSec);
                setRateText(el.ratePushes, d.pushes, prev && prev.pushes, dtSec);
                setRateText(el.rateTotalRec, d.total_records, prev && prev.total_records, dtSec);
                setRateText(el.rateVconsidered, d.scoring_versions_considered, prev && prev.scoring_versions_considered, dtSec);
                setRateText(el.rateFallback, d.scoring_fallback_latest, prev && prev.scoring_fallback_latest, dtSec);

                pushSparklinePoint('errors', d.errors || 0);
                pushSparklinePoint('timeouts', d.timeouts || 0);
                pushSparklinePoint('rejects', d.decoder_rejects || 0);
                pushSparklinePoint('append', d.append_failures || 0);
                pushSparklinePoint('overflow', d.index_overflows || 0);
                pushSparklinePoint('upstream', d.upstream_errors || 0);
                el.sparkErrors.textContent = toSparkline(metricSparkHistory.errors);
                el.sparkTimeouts.textContent = toSparkline(metricSparkHistory.timeouts);
                el.sparkRejects.textContent = toSparkline(metricSparkHistory.rejects);
                el.sparkAppend.textContent = toSparkline(metricSparkHistory.append);
                el.sparkOverflow.textContent = toSparkline(metricSparkHistory.overflow);
                el.sparkUpErr.textContent = toSparkline(metricSparkHistory.upstream);

                const p5 = Number(d.lumina_v5p || 0);
                const p0 = Number(d.lumina_v0_4 || 0);
                const totalProto = Math.max(1, p5 + p0);
                const p5Pct = (p5 / totalProto) * 100;
                const deg = Math.round((p5Pct / 100) * 360);
                el.protoMixDonut.style.background = 'conic-gradient(var(--accent) 0deg, var(--accent) ' + deg + 'deg, rgba(255, 102, 0, 0.8) ' + deg + 'deg, rgba(255, 102, 0, 0.8) 360deg)';
                el.protoMixLabel.textContent = 'V5 ' + p5Pct.toFixed(1) + '% / LEG ' + (100 - p5Pct).toFixed(1) + '%';

                setMetricIndicator(el.mIndexed, d.indexed_funcs);
                setMetricIndicator(el.mStorage, d.storage_bytes);
                setMetricIndicator(el.mSearchDocs, d.search_docs);
                setMetricIndicator(el.mBinaries, d.unique_binaries);
                setMetricIndicator(el.mQueried, d.queried_funcs);
                setMetricIndicator(el.mRpc, d.active_connections);
                setMetricIndicator(el.mUpstream, d.upstream_requests);
                setMetricIndicator(el.mFetched, d.upstream_fetched);
                setMetricIndicator(el.mNew, d.new_funcs);
                setMetricIndicator(el.mPulls, d.pulls);
                setMetricIndicator(el.mPushes, d.pushes);
                setMetricIndicator(el.mScoring, d.scoring_batches);

                el.statusRing.classList.remove('offline');
                el.statusLabel.classList.remove('offline');
                el.statusLabel.textContent = 'OPERATIONAL';
                el.indexStatus.textContent = 'READY';
                el.telStorage.className = 'dot ' + ((d.append_failures || 0) > 0 ? 'error' : 'active');
                el.telIndex.className = 'dot ' + ((d.index_overflows || 0) > 0 ? 'warn' : 'active');
                el.telNetwork.className = 'dot ' + ((d.errors || 0) > 0 ? 'warn' : 'active');
                el.telUpstream.className = 'dot ' + ((d.upstream_requests || 0) > 0 ? 'active' : '');
                el.uptime.textContent = fmtUptime(d.uptime_secs || 0);

                metricsPrevSnapshot = d;
                metricsPrevTsMs = nowMs;
            } catch (e) {
                el.statusRing.classList.add('offline');
                el.statusLabel.classList.add('offline');
                el.statusLabel.textContent = 'OFFLINE';
                el.indexStatus.textContent = 'ERROR';
            }
        }

        function showDashboard(updateUrl = true) {
            hideFullPages();
            el.dashboard.classList.remove('hidden');
            el.secondary.classList.remove('hidden');
            el.results.classList.remove('active');
            el.comparePanel.classList.add('hidden');
            el.pagination.innerHTML = '';
            currentPage = 1;
            currentQuery = '';
            currentHits = [];
            selectedResultIndex = -1;
            openPreviewKey = null;
            if (updateUrl) syncHashWithUi();
        }

        async function runSearch(query, page = 1, updateUrl = true) {
            query = query.trim();
            if (!query) { showDashboard(updateUrl); return; }

            currentQuery = query;
            currentPage = page;

            hideFullPages();
            el.dashboard.classList.add('hidden');
            el.secondary.classList.add('hidden');
            el.results.classList.add('active');
            el.comparePanel.classList.toggle('hidden', currentSearchMode !== 'functions');
            el.resultsQuery.textContent = query;
            el.resultsList.innerHTML = '<div class="state-message"><div class="icon">&gt;&gt;&gt;</div><h3>QUERYING INDEX</h3><p>Processing request...</p></div>';
            el.pagination.innerHTML = '';

            if (updateUrl) syncHashWithUi();

            const t0 = performance.now();
            try {
                const r = await fetch('/api/search?mode=' + encodeURIComponent(currentSearchMode) + '&q=' + encodeURIComponent(query) + '&page=' + page);
                if (!r.ok) throw new Error('Query failed: ' + r.status);
                const d = await r.json();
                renderResults(d, query, performance.now() - t0);
            } catch (e) {
                el.resultsList.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>QUERY ERROR</h3><p>' + esc(e.message) + '</p></div>';
                el.resultsCount.textContent = '0';
                el.resultsTotalLabel.textContent = '';
                el.pagination.innerHTML = '';
            }
        }

        function renderResults(data, query, latency) {
            const { results: hits, total, page, per_page, total_pages } = data;
            el.resultsLatency.textContent = latency.toFixed(1) + 'ms';
            setResultsIntent(query);

            if (!hits || hits.length === 0) {
                el.resultsCount.textContent = '0';
                el.resultsTotalLabel.textContent = '';
                el.resultsList.innerHTML = '<div class="state-message"><div class="icon">[ ]</div><h3>NO MATCHES FOUND</h3><p>Query "' + esc(query) + '" returned no results.</p></div>';
                el.pagination.innerHTML = '';
                currentHits = [];
                currentTotalPages = 0;
                return;
            }

            currentHits = hits;
            currentTotal = total;
            currentTotalPages = total_pages;
            currentPerPage = per_page;
            selectedResultIndex = hits.length > 0 ? 0 : -1;
            el.resultsCount.textContent = hits.length;
            el.resultsTotalLabel.textContent = 'of ' + fmt(total) + ' total';

            renderResultsList();
            renderPagination(page, total_pages, total);
        }

        function renderResultsList() {
            const hits = sortHits(currentHits, currentSort);
            if (hits.length === 0) {
                el.resultsList.innerHTML = '';
                return;
            }
            if (currentSearchMode === 'binaries') {
                renderBinaryResultsList(hits);
                return;
            }
            const minScore = Math.min(...hits.map(h => Number(h.score || 0)));
            const maxScore = Math.max(...hits.map(h => Number(h.score || 0)));
            const startIdx = (currentPage - 1) * currentPerPage;

            el.resultsList.innerHTML = hits.map((h, i) => {
                const bins = (h.binaries || []).map(b => '<span class="bin-tag clickable" onclick="event.stopPropagation();openBinaryFromFunction(\'' + esc(b.md5_hex) + '\', \'' + encodeURIComponent(b.basename) + '\')">' + esc(b.basename) + '<span class="accent">#' + esc(b.short_id) + '</span></span>').join('');
                const displayName = h.func_name_demangled || h.func_name;
                const displayNameHtml = renderCompactSignatureText(displayName, false);
                const langBadge = h.lang ? '<span class="lang-badge">' + esc(h.lang.toUpperCase()) + '</span>' : '';
                const mangledHint = h.func_name_demangled ? '<div class="result-mangled" title="Mangled name">' + esc(h.func_name) + '</div>' : '';
                const scoreRatio = normalizeScore(Number(h.score || 0), minScore, maxScore);
                const isPinned = pinnedKeys.has(h.key_hex);
                const inCompare = compareKeys.includes(h.key_hex);
                const isPreviewOpen = openPreviewKey === h.key_hex;
                const isSelected = i === selectedResultIndex;
                const age = fmtRelativeTs(h.ts);
                const copied = copiedKeyHex === h.key_hex;

                return '<div class="result-item clickable' + (isSelected ? ' selected' : '') + '" data-result-index="' + i + '" onclick="showFunctionDetail(\'' + esc(h.key_hex) + '\')">'
                    + '<div class="result-index">' + String(startIdx + i + 1).padStart(2, '0') + '</div>'
                    + '<div class="result-main"><div class="result-func">' + displayNameHtml + '</div>' + mangledHint + '<div class="result-key"><span class="result-key-copy' + (copied ? ' copied' : '') + '" onclick="event.stopPropagation();copyResultKey(\'' + esc(h.key_hex) + '\')">KEY ' + esc(h.key_hex) + '</span><span class="result-age">' + esc(age) + '</span></div><div class="result-bins">' + bins + '</div></div>'
                    + '<div class="result-meta">' + langBadge + '<span class="version-badge age">' + esc(age) + '</span><span class="score-badge">SCORE ' + Number(h.score).toFixed(2) + '</span><div class="score-meter"><div class="score-meter-fill" style="width:' + (scoreRatio * 100).toFixed(1) + '%;"></div></div><div class="result-actions">'
                    + '<button class="result-action' + (isPinned ? ' active' : '') + '" onclick="event.stopPropagation();togglePin(\'' + esc(h.key_hex) + '\')">pin</button>'
                    + '<button class="result-action' + (inCompare ? ' active' : '') + '" onclick="event.stopPropagation();toggleCompareKey(\'' + esc(h.key_hex) + '\')">cmp</button>'
                    + '<button class="result-action' + (isPreviewOpen ? ' active' : '') + '" onclick="event.stopPropagation();togglePreview(\'' + esc(h.key_hex) + '\')">peek</button>'
                    + '</div></div>'
                    + '<div class="result-preview' + (isPreviewOpen ? ' active' : '') + '">' + (isPreviewOpen ? previewHtmlForKey(h.key_hex) : '') + '</div>'
                    + '</div>';
            }).join('');
        }

        function renderBinaryResultsList(hits) {
            const minScore = Math.min(...hits.map(h => Number(h.score || 0)));
            const maxScore = Math.max(...hits.map(h => Number(h.score || 0)));
            const startIdx = (currentPage - 1) * currentPerPage;
            el.resultsList.innerHTML = hits.map((h, i) => {
                const scoreRatio = normalizeScore(Number(h.score || 0), minScore, maxScore);
                const selected = h.md5_hex === currentBinaryMd5;
                return '<div class="result-item clickable' + (selected ? ' selected' : '') + '" onclick="showBinaryDetail(\'' + esc(h.md5_hex) + '\')">'
                    + '<div class="result-index">' + String(startIdx + i + 1).padStart(2, '0') + '</div>'
                    + '<div class="result-main"><div class="result-func">' + esc(h.display_name) + '</div>'
                    + '<div class="result-key"><span class="result-key-copy" onclick="event.stopPropagation();copyText(\'' + esc(h.md5_hex) + '\')">MD5 ' + esc(h.md5_hex) + '</span><span class="result-age">' + esc(fmtRelativeTs(h.last_seen_ts)) + '</span></div>'
                    + '<div class="result-bins"><span class="bin-tag">FUNCTIONS ' + fmt(h.function_count || 0) + '</span><span class="bin-tag">TYPED FUNCTIONS ' + fmt(h.typed_functions || 0) + '</span><span class="bin-tag">OBSERVATIONS ' + fmt(h.obs_count || 0) + '</span></div></div>'
                    + '<div class="result-meta"><span class="score-badge">SCORE ' + Number(h.score || 0).toFixed(2) + '</span><div class="score-meter"><div class="score-meter-fill" style="width:' + (scoreRatio * 100).toFixed(1) + '%;"></div></div></div>'
                    + '</div>';
            }).join('');
        }

        function renderPagination(page, totalPages, total) {
            if (totalPages <= 1) {
                el.pagination.innerHTML = '';
                return;
            }

            let html = '<button class="pagination-btn" onclick="goToPage(' + (page - 1) + ')"' + (page <= 1 ? ' disabled' : '') + '>&lt;&lt; PREV</button>';
            html += '<span class="pagination-info">PAGE <span class="accent">' + page + '</span> OF <span class="accent">' + totalPages + '</span></span>';
            html += '<button class="pagination-btn" onclick="goToPage(' + (page + 1) + ')"' + (page >= totalPages ? ' disabled' : '') + '>NEXT &gt;&gt;</button>';

            el.pagination.innerHTML = html;
        }

        function goToPage(page) {
            if (page < 1 || !currentQuery) return;
            runSearch(currentQuery, page, true);
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function setSelectedResultIndex(idx) {
            const hits = sortHits(currentHits, currentSort);
            if (hits.length === 0) {
                selectedResultIndex = -1;
                return;
            }
            selectedResultIndex = Math.max(0, Math.min(hits.length - 1, idx));
            renderResultsList();
            const row = document.querySelector('[data-result-index="' + selectedResultIndex + '"]');
            if (row) row.scrollIntoView({ block: 'nearest' });
        }

        function handleResultsKeyNav(e) {
            if (!el.results.classList.contains('active') || isDetailPageOpen() || isComparePageOpen()) return;
            if (document.activeElement === el.q || document.activeElement === el.resultsSort) return;
            const hits = sortHits(currentHits, currentSort);
            if (hits.length === 0) return;

            if (e.key === 'j') {
                e.preventDefault();
                setSelectedResultIndex(selectedResultIndex < 0 ? 0 : selectedResultIndex + 1);
            } else if (e.key === 'k') {
                e.preventDefault();
                setSelectedResultIndex(selectedResultIndex < 0 ? 0 : selectedResultIndex - 1);
            } else if (e.key === 'Enter' && selectedResultIndex >= 0) {
                e.preventDefault();
                if (currentSearchMode === 'binaries') showBinaryDetail(hits[selectedResultIndex].md5_hex);
                else showFunctionDetail(hits[selectedResultIndex].key_hex);
            } else if (e.key === ' ' && currentSearchMode === 'functions') {
                if (selectedResultIndex >= 0) {
                    e.preventDefault();
                    togglePreview(hits[selectedResultIndex].key_hex);
                }
            } else if (e.key === 'c' && currentSearchMode === 'functions' && selectedResultIndex >= 0) {
                e.preventDefault();
                toggleCompareKey(hits[selectedResultIndex].key_hex);
            } else if (e.key === 'p' && currentSearchMode === 'functions' && selectedResultIndex >= 0) {
                e.preventDefault();
                togglePin(hits[selectedResultIndex].key_hex);
            }
        }

        function handleSearchInput() {
            if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
            searchDebounceTimer = setTimeout(() => runSearch(el.q.value, 1), DEBOUNCE_MS);
        }

        el.q.addEventListener('input', handleSearchInput);
        el.q.addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                if (searchDebounceTimer) { clearTimeout(searchDebounceTimer); searchDebounceTimer = null; }
                runSearch(el.q.value, 1);
            }
        });
        document.addEventListener('keydown', e => {
            if (e.key === '/' && document.activeElement !== el.q) { e.preventDefault(); el.q.focus(); }
        });
        document.addEventListener('keydown', handleResultsKeyNav);

        el.resultsSort.addEventListener('change', e => {
            currentSort = e.target.value || 'score';
            renderResultsList();
        });
        el.compareClear.addEventListener('click', clearCompareKeys);
        el.compareOpen.addEventListener('click', openCompareModal);
        el.compareSave.addEventListener('click', saveCompareSet);
        el.compareExport.addEventListener('click', exportCompareSet);
        el.compareImport.addEventListener('click', () => el.compareImportFile.click());
        el.compareLoad.addEventListener('change', e => loadCompareSet(e.target.value));
        el.compareImportFile.addEventListener('change', async e => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            try {
                const text = await file.text();
                importCompareSetFromText(text);
            } catch (err) {
                alert('Failed to import compare set: ' + (err.message || String(err)));
            } finally {
                e.target.value = '';
            }
        });
        window.addEventListener('hashchange', () => {
            if (suppressHashHandler) return;
            applyHashState(parseHash());
        });

        updateTime();
        setInterval(updateTime, 1000);
        fetchMetrics();
        setInterval(fetchMetrics, 5000);
        restoreCompareState();
        restoreSemanticNeighborPrefs();
        updateCompareTray();
        hydrateCompareItems(compareKeys);
        refreshCompareLoadOptions();
        applySearchModeUi();

        applyHashState(parseHash());

        // ═══════════════════════════════════════════════════════════════
        // FUNCTION DETAIL MODAL
        // ═══════════════════════════════════════════════════════════════

        function showFunctionDetail(keyHex, sectionId = null, updateUrl = true) {
            setSearchMode('functions', false, false);
            hideFullPages();
            currentDetailKind = 'function';
            currentDetailData = null;
            currentDetailKeyHex = keyHex;
            currentSemanticNeighbors = null;
            currentSemanticNeighborLoadedSig = null;
            currentSemanticNeighborLoadingSig = null;
            currentSemanticNeighborError = null;
            currentBinaryMd5 = null;
            currentBinaryCompareData = null;
            currentGraphHoverMd5 = null;
            currentGraphFocusMd5 = null;
            currentCompareRecords = [];
            pendingDetailSection = sectionId;
            selectedControlFlowGroup = null;
            selectedControlFlowRow = null;
            selectedControlFlowCase = null;
            controlFlowFocusMode = false;
            currentDetailSection = sectionId || null;
            el.modalTitle.innerHTML = 'FUNCTION DETAIL // <span id="modal-key"></span>';
            el.modalKey = document.getElementById('modal-key');
            activateFullPage('detail');
            el.modalKey.textContent = keyHex;
            el.modalBody.innerHTML = '<div class="detail-loading">&gt;&gt;&gt; LOADING METADATA...</div>';
            if (updateUrl) syncHashWithUi();

            fetch('/api/function/' + encodeURIComponent(keyHex))
                .then(r => {
                    if (!r.ok) throw new Error('Failed to fetch: ' + r.status);
                    return r.json();
                })
                .then(data => renderFunctionDetail(data))
                .catch(err => {
                    el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>FETCH ERROR</h3><p>' + esc(err.message) + '</p></div>';
                });
        }

        function semanticNeighborRequestSig(keyHex) {
            return String(keyHex || '') + '|' + String(currentSemanticNeighborLimit) + '|' + (currentSemanticNeighborStrictFamily ? '1' : '0');
        }

        function functionDetailHref(keyHex, sectionId = '') {
            const state = parseHash();
            const params = new URLSearchParams();
            const mode = (state && state.m) ? state.m : currentSearchMode;
            const query = (state && state.q) ? state.q : currentQuery;
            const page = state && state.page ? state.page : currentPage;
            if (mode && mode !== 'functions') params.set('m', mode);
            if (query) params.set('q', query);
            if (query && page > 1) params.set('page', String(page));
            if (keyHex) params.set('f', keyHex);
            if (sectionId) params.set('s', sectionId);
            const hash = params.toString();
            return hash ? ('#' + hash) : '#';
        }

        function reloadSemanticNeighbors() {
            if (currentDetailKind !== 'function' || !currentDetailKeyHex) return;
            currentSemanticNeighbors = null;
            currentSemanticNeighborLoadedSig = null;
            currentSemanticNeighborError = null;
            ensureSemanticNeighborsLoaded(currentDetailKeyHex);
            if (currentDetailData && currentDetailData.key_hex === currentDetailKeyHex) {
                renderFunctionDetail(currentDetailData);
            }
        }

        function setSemanticNeighborLimit(value) {
            const parsed = Math.max(1, Math.min(24, Number.parseInt(value, 10) || 8));
            if (parsed === currentSemanticNeighborLimit) return;
            currentSemanticNeighborLimit = parsed;
            persistSemanticNeighborPrefs();
            reloadSemanticNeighbors();
        }

        function setSemanticNeighborStrictFamily(enabled) {
            const next = !!enabled;
            if (next === currentSemanticNeighborStrictFamily) return;
            currentSemanticNeighborStrictFamily = next;
            persistSemanticNeighborPrefs();
            reloadSemanticNeighbors();
        }

        function toggleSemanticNeighborStrictFamily() {
            setSemanticNeighborStrictFamily(!currentSemanticNeighborStrictFamily);
        }

        function ensureSemanticNeighborsLoaded(keyHex) {
            if (!keyHex) return;
            const requestSig = semanticNeighborRequestSig(keyHex);
            if (currentSemanticNeighborLoadingSig === requestSig) return;
            if (currentSemanticNeighborLoadedSig === requestSig && (Array.isArray(currentSemanticNeighbors) || currentSemanticNeighborError)) return;

            currentSemanticNeighborLoadingSig = requestSig;
            currentSemanticNeighborError = null;
            fetch('/api/function/' + encodeURIComponent(keyHex) + '/neighbors?limit=' + encodeURIComponent(currentSemanticNeighborLimit) + '&strict_family=' + (currentSemanticNeighborStrictFamily ? '1' : '0'))
                .then(r => {
                    if (!r.ok) throw new Error('Failed to fetch neighbors: ' + r.status);
                    return r.json();
                })
                .then(data => {
                    if (currentDetailKind !== 'function' || currentDetailKeyHex !== keyHex || semanticNeighborRequestSig(keyHex) !== requestSig) return;
                    currentSemanticNeighborLoadingSig = null;
                    currentSemanticNeighborLoadedSig = requestSig;
                    currentSemanticNeighbors = Array.isArray(data && data.results) ? data.results : [];
                    currentSemanticNeighborError = null;
                    if (currentDetailData && currentDetailData.key_hex === keyHex) renderFunctionDetail(currentDetailData);
                })
                .catch(err => {
                    if (currentDetailKind !== 'function' || currentDetailKeyHex !== keyHex || semanticNeighborRequestSig(keyHex) !== requestSig) return;
                    currentSemanticNeighborLoadingSig = null;
                    currentSemanticNeighborLoadedSig = requestSig;
                    currentSemanticNeighbors = [];
                    currentSemanticNeighborError = err.message || String(err);
                    if (currentDetailData && currentDetailData.key_hex === keyHex) renderFunctionDetail(currentDetailData);
                });
        }

        function openBinaryFromFunction(md5Hex, basenameEncoded) {
            const basename = basenameEncoded ? decodeURIComponent(basenameEncoded) : '';
            setSearchMode('binaries', false, false);
            if (basename) {
                el.q.value = basename;
                runSearch(basename, 1, false).then(() => showBinaryDetail(md5Hex));
            } else {
                showBinaryDetail(md5Hex);
            }
        }

        function showBinaryDetail(md5Hex, updateUrl = true) {
            hideFullPages();
            currentDetailKind = 'binary';
            currentDetailData = null;
            currentDetailKeyHex = null;
            currentBinaryMd5 = md5Hex;
            currentBinaryCompareData = null;
            currentBinaryGraphDepth = 2;
            currentBinaryGraphLimit = 6;
            currentBinaryCompareLimit = 18;
            currentBinaryCompareMode = 'all';
            currentBinaryCompareQuery = '';
            currentBinaryComparePage = 1;
            currentGraphHoverMd5 = null;
            currentGraphFocusMd5 = null;
            currentBinaryGraphZoom = 1;
            currentCompareRecords = [];
            el.modalTitle.innerHTML = 'BINARY DETAIL // <span id="modal-key"></span>';
            el.modalKey = document.getElementById('modal-key');
            el.modalKey.textContent = md5Hex;
            pendingDetailSection = null;
            currentDetailSection = null;
            el.modalTitle.innerHTML = 'BINARY DETAIL // <span id="modal-key"></span>';
            activateFullPage('detail');
            el.modalKey.textContent = md5Hex;
            el.modalBody.innerHTML = '<div class="detail-loading">&gt;&gt;&gt; LOADING BINARY PROFILE...</div>';
            if (updateUrl) syncHashWithUi();

            fetch('/api/binary/' + encodeURIComponent(md5Hex))
                .then(r => {
                    if (!r.ok) throw new Error('Failed to fetch: ' + r.status);
                    return r.json();
                })
                .then(data => renderBinaryDetail(data))
                .catch(err => {
                    el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>FETCH ERROR</h3><p>' + esc(err.message) + '</p></div>';
                });
        }

        function closeDetailModal(updateUrl = true) {
            restorePrimarySurface();
            currentDetailData = null;
            currentDetailKind = 'function';
            currentDetailKeyHex = null;
            if (currentSearchMode !== 'binaries') {
                currentBinaryMd5 = null;
                currentBinaryCompareData = null;
            }
            currentCompareRecords = [];
            pendingDetailSection = null;
            selectedControlFlowGroup = null;
            selectedControlFlowRow = null;
            selectedControlFlowCase = null;
            controlFlowFocusMode = false;
            currentDetailSection = null;
            if (updateUrl) syncHashWithUi();
            if (activeCommentRow) {
                activeCommentRow.classList.remove('active');
                activeCommentRow = null;
            }
            if (activeCommentRowTimer) {
                clearTimeout(activeCommentRowTimer);
                activeCommentRowTimer = null;
            }
            if (activeCommentMarker) {
                activeCommentMarker.classList.remove('active');
                activeCommentMarker = null;
            }
            if (activeCommentMarkerTimer) {
                clearTimeout(activeCommentMarkerTimer);
                activeCommentMarkerTimer = null;
            }
        }

        el.modalBody.addEventListener('scroll', () => {
            if (currentDetailKind !== 'function') return;
            if (detailScrollSyncRaf) cancelAnimationFrame(detailScrollSyncRaf);
            detailScrollSyncRaf = requestAnimationFrame(() => {
                detailScrollSyncRaf = null;
                syncDetailSectionFromScroll();
            });
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape' && isComparePageOpen()) {
                closeBinaryCompareModal();
                return;
            }
            if (e.key === 'Escape' && isDetailPageOpen()) {
                closeDetailModal();
            }
        });

        async function loadBinaryFunctionsPage(md5Hex, page) {
            if (!md5Hex) return;
            try {
                const r = await fetch('/api/binary/' + encodeURIComponent(md5Hex) + '/functions?page=' + page);
                if (!r.ok) throw new Error('Failed to fetch: ' + r.status);
                const functions = await r.json();
                if (currentDetailKind === 'binary' && currentBinaryMd5 === md5Hex && currentDetailData) {
                    currentDetailData.functions = functions;
                    renderBinaryDetail(currentDetailData);
                }
            } catch (err) {
                alert('Failed to load binary functions: ' + (err.message || String(err)));
            }
        }

        async function loadBinaryCompare(otherMd5Hex) {
            if (!currentBinaryMd5 || !otherMd5Hex) return;
            openBinaryCompareModal();
            try {
                const params = new URLSearchParams();
                params.set('limit', String(currentBinaryCompareLimit));
                params.set('mode', currentBinaryCompareMode);
                params.set('page', String(currentBinaryComparePage));
                params.set('per_page', String(BINARY_COMPARE_PAGE_SIZE));
                if (currentBinaryCompareQuery) params.set('q', currentBinaryCompareQuery);
                const r = await fetch('/api/binary-compare/' + encodeURIComponent(currentBinaryMd5) + '/' + encodeURIComponent(otherMd5Hex) + '?' + params.toString());
                if (!r.ok) throw new Error('Failed to fetch: ' + r.status);
                currentBinaryCompareData = await r.json();
                renderBinaryCompareView();
                syncHashWithUi();
            } catch (err) {
                el.binaryCompareBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>COMPARE ERROR</h3><p>' + esc(err.message || String(err)) + '</p></div>';
            }
        }

        async function loadBinaryGraph(depth, limit) {
            if (!currentBinaryMd5) return;
            currentBinaryGraphDepth = Math.max(1, Math.min(3, Number(depth || currentBinaryGraphDepth || 2)));
            currentBinaryGraphLimit = Math.max(1, Math.min(16, Number(limit || currentBinaryGraphLimit || 6)));
            try {
                const r = await fetch('/api/binary/' + encodeURIComponent(currentBinaryMd5) + '/graph?depth=' + currentBinaryGraphDepth + '&limit=' + currentBinaryGraphLimit);
                if (!r.ok) throw new Error('Failed to fetch: ' + r.status);
                const graphPayload = await r.json();
                if (currentDetailKind === 'binary' && currentDetailData) {
                    currentDetailData.graph = graphPayload.graph || { nodes: [], edges: [] };
                    renderBinaryDetail(currentDetailData);
                }
            } catch (err) {
                alert('Failed to load overlap graph: ' + (err.message || String(err)));
            }
        }

        function setBinaryCompareLimit(limit) {
            currentBinaryCompareLimit = Math.max(1, Math.min(100, Number(limit || currentBinaryCompareLimit || 18)));
            currentBinaryComparePage = 1;
            if (currentBinaryCompareData && currentBinaryCompareData.right && currentBinaryCompareData.right.md5_hex) {
                loadBinaryCompare(currentBinaryCompareData.right.md5_hex);
            }
            syncHashWithUi();
        }

        function setBinaryCompareMode(mode) {
            currentBinaryCompareMode = mode || 'all';
            currentBinaryComparePage = 1;
            if (currentBinaryCompareData && currentBinaryCompareData.right && currentBinaryCompareData.right.md5_hex) {
                loadBinaryCompare(currentBinaryCompareData.right.md5_hex);
            } else {
                renderBinaryCompareView();
                syncHashWithUi();
            }
        }

        function openBinaryCompareModal() {
            activateFullPage('compare');
            el.binaryCompareBody.innerHTML = '<div class="detail-loading">&gt;&gt;&gt; LOADING COMPARE...</div>';
            syncHashWithUi();
        }

        function closeBinaryCompareModal() {
            if (currentBinaryMd5 && currentDetailKind === 'binary' && currentDetailData) activateFullPage('detail');
            else restorePrimarySurface();
            syncHashWithUi();
        }

        function setGraphHover(md5Hex) {
            currentGraphHoverMd5 = md5Hex || null;
            if (currentDetailKind === 'binary' && currentDetailData) renderBinaryDetail(currentDetailData);
        }

        function setGraphFocus(md5Hex) {
            currentGraphFocusMd5 = currentGraphFocusMd5 === md5Hex ? null : md5Hex;
            if (currentDetailKind === 'binary' && currentDetailData) renderBinaryDetail(currentDetailData);
        }

        function setBinaryGraphZoom(delta) {
            currentBinaryGraphZoom = Math.max(0.75, Math.min(1.8, Number(currentBinaryGraphZoom || 1) + Number(delta || 0)));
            if (currentDetailKind === 'binary' && currentDetailData) renderBinaryDetail(currentDetailData);
        }

        function setBinaryCompareQuery(value) {
            currentBinaryCompareQuery = value || '';
            currentBinaryComparePage = 1;
            if (currentBinaryCompareData && currentBinaryCompareData.right) loadBinaryCompare(currentBinaryCompareData.right.md5_hex);
        }

        function setBinaryComparePage(page) {
            currentBinaryComparePage = Math.max(1, Number(page || 1));
            if (currentBinaryCompareData && currentBinaryCompareData.right) loadBinaryCompare(currentBinaryCompareData.right.md5_hex);
        }

        function exportBinaryCompareReport() {
            if (!currentBinaryCompareData) return;
            const blob = new Blob([JSON.stringify(currentBinaryCompareData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'binary-compare-' + (currentBinaryCompareData.left && currentBinaryCompareData.left.short_id ? currentBinaryCompareData.left.short_id : 'left') + '-' + (currentBinaryCompareData.right && currentBinaryCompareData.right.short_id ? currentBinaryCompareData.right.short_id : 'right') + '.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        }

        function exportBinaryCompareMarkdown() {
            if (!currentBinaryCompareData) return;
            const compare = currentBinaryCompareData;
            const lines = [];
            lines.push('# Binary Compare');
            lines.push('');
            lines.push('- Left: ' + (compare.left.display_name || compare.left.basename));
            lines.push('- Right: ' + (compare.right.display_name || compare.right.basename));
            lines.push('- Shared: ' + fmt(compare.shared_count || 0));
            lines.push('- Left Only: ' + fmt(compare.left_only_count || 0));
            lines.push('- Right Only: ' + fmt(compare.right_only_count || 0));
            lines.push('');
            lines.push('## Active Bucket');
            lines.push('');
            lines.push('- Bucket: ' + (compare.active_bucket || 'All'));
            lines.push('- Query: ' + (compare.active_bucket_query || '-'));
            lines.push('- Page: ' + fmt(compare.active_bucket_page || 1) + ' / ' + fmt(compare.active_bucket_total_pages || 1));
            lines.push('');
            (compare.active_bucket_items || []).forEach(item => {
                lines.push('- `' + item.key_hex + '` ' + item.name + ' (rarity ' + fmt(item.rarity_score || 0) + ', cover ' + fmt(item.richness_score || 0) + ', ' + fmtRelativeTs(item.ts) + ')');
            });
            const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'binary-compare-' + (compare.left.short_id || 'left') + '-' + (compare.right.short_id || 'right') + '.md';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        }

        function exportBinaryCompareCsv() {
            if (!currentBinaryCompareData) return;
            const compare = currentBinaryCompareData;
            const rows = [['bucket','key_hex','name','rarity_score','richness_score','ts']];
            (compare.active_bucket_items || []).forEach(item => {
                rows.push([
                    compare.active_bucket || 'All',
                    item.key_hex || '',
                    item.name || '',
                    String(item.rarity_score || 0),
                    String(item.richness_score || 0),
                    String(item.ts || 0),
                ]);
            });
            const csv = rows.map(row => row.map(value => '"' + String(value).replace(/"/g, '""') + '"').join(',')).join('\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'binary-compare-' + (compare.left.short_id || 'left') + '-' + (compare.right.short_id || 'right') + '.csv';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        }

        function renderBinaryFacetCard(label, value, total) {
            const pct = total > 0 ? Math.round((Number(value || 0) / Number(total || 1)) * 100) : 0;
            return '<div class="coverage-card"><div class="label">' + esc(label) + '</div><div class="value">' + fmt(value || 0) + '<span class="detail-label"> // ' + pct + '%</span></div></div>';
        }

        function comparePresetDescription(mode) {
            switch (mode) {
                case 'Shared': return 'Functions present in both binaries.';
                case 'Left Only': return 'Functions only observed in the left binary.';
                case 'Right Only': return 'Functions only observed in the right binary.';
                case 'Recent': return 'Most recently observed functions across the compared set.';
                case 'Metadata Rich': return 'Functions with the richest type, frame, comment, and decompilation signal.';
                case 'Rare Symbols': return 'Functions associated with fewer binaries, useful for discriminators.';
                case 'Freshest Drift': return 'Recently observed functions that diverge between left and right.';
                default: return 'Overview of the three primary diff buckets.';
            }
        }

        function renderCoverageStrip(binary, facetsOverride) {
            const total = Math.max(1, Number((facetsOverride && facetsOverride.function_count) || binary.function_count || 1));
            const typed = Number((facetsOverride && facetsOverride.typed_functions) || binary.typed_functions || 0);
            const commented = Number((facetsOverride && facetsOverride.commented_functions) || binary.commented_functions || 0);
            const switchy = Number((facetsOverride && facetsOverride.switch_functions) || binary.switch_functions || 0);
            const rows = [
                ['Typed', typed],
                ['Comments', commented],
                ['Switches', switchy],
            ];
            return '<div class="coverage-strip">' + rows.map(([label, value]) => {
                const pct = Math.round((Number(value) / total) * 100);
                return '<div class="coverage-strip-row"><span>' + esc(label) + '</span><div class="coverage-strip-bar"><div class="coverage-strip-fill" style="width:' + pct + '%"></div></div><span>' + pct + '%</span></div>';
            }).join('') + '</div>';
        }

        function shortenBinaryName(name) {
            const text = basenameOnly(name);
            if (text.length <= 28) return text;
            return text.slice(0, 25) + '...';
        }

        function basenameOnly(name) {
            const text = String(name || '');
            const normalized = text.replace(/\\/g, '/');
            const idx = normalized.lastIndexOf('/');
            return idx >= 0 ? normalized.slice(idx + 1) : normalized;
        }

        function renderBinaryName(binary) {
            const base = basenameOnly((binary && (binary.basename || binary.display_name)) || '');
            const short = binary && binary.short_id ? binary.short_id : '';
            return short ? (base + ' · ' + short) : base;
        }

        function renderBinaryTitle(binary) {
            const base = basenameOnly((binary && (binary.basename || binary.display_name)) || '');
            const short = binary && binary.short_id ? binary.short_id : '';
            return '<div class="binary-name-row"><div class="detail-value accent binary-title">' + esc(base) + '</div>'
                + (short ? '<span class="binary-short-id">' + esc(short) + '</span>' : '')
                + '</div>';
        }

        function findTopLevelChar(text, target) {
            let angle = 0;
            let paren = 0;
            let bracket = 0;
            for (let i = 0; i < text.length; i++) {
                const ch = text[i];
                if (ch === target && angle === 0 && paren === 0 && bracket === 0) return i;
                if (ch === '<') angle += 1;
                else if (ch === '>') angle = Math.max(0, angle - 1);
                else if (ch === '(') paren += 1;
                else if (ch === ')') paren = Math.max(0, paren - 1);
                else if (ch === '[') bracket += 1;
                else if (ch === ']') bracket = Math.max(0, bracket - 1);
            }
            return -1;
        }

        function findMatchingAngle(text, start) {
            let depth = 0;
            for (let i = start; i < text.length; i++) {
                const ch = text[i];
                if (ch === '<') depth += 1;
                else if (ch === '>') {
                    depth -= 1;
                    if (depth === 0) return i;
                }
            }
            return -1;
        }

        function splitTopLevel(text, separator = ',') {
            const out = [];
            let angle = 0;
            let paren = 0;
            let bracket = 0;
            let current = '';
            for (let i = 0; i < text.length; i++) {
                const ch = text[i];
                if (ch === '<') angle += 1;
                else if (ch === '>') angle = Math.max(0, angle - 1);
                else if (ch === '(') paren += 1;
                else if (ch === ')') paren = Math.max(0, paren - 1);
                else if (ch === '[') bracket += 1;
                else if (ch === ']') bracket = Math.max(0, bracket - 1);
                if (ch === separator && angle === 0 && paren === 0 && bracket === 0) {
                    if (current.trim()) out.push(current.trim());
                    current = '';
                    continue;
                }
                current += ch;
            }
            if (current.trim()) out.push(current.trim());
            return out;
        }

        function stripOuterParens(text) {
            let value = (text || '').trim();
            while (value.startsWith('(') && value.endsWith(')')) {
                let depth = 0;
                let balanced = true;
                for (let i = 0; i < value.length; i++) {
                    const ch = value[i];
                    if (ch === '(') depth += 1;
                    else if (ch === ')') {
                        depth -= 1;
                        if (depth === 0 && i < value.length - 1) {
                            balanced = false;
                            break;
                        }
                    }
                }
                if (!balanced || depth !== 0) break;
                value = value.slice(1, -1).trim();
            }
            return value;
        }

        function splitTopLevelWhitespace(text) {
            const out = [];
            let angle = 0;
            let paren = 0;
            let bracket = 0;
            let current = '';
            for (let i = 0; i < text.length; i++) {
                const ch = text[i];
                if (ch === '<') angle += 1;
                else if (ch === '>') angle = Math.max(0, angle - 1);
                else if (ch === '(') paren += 1;
                else if (ch === ')') paren = Math.max(0, paren - 1);
                else if (ch === '[') bracket += 1;
                else if (ch === ']') bracket = Math.max(0, bracket - 1);
                if (/\s/.test(ch) && angle === 0 && paren === 0 && bracket === 0) {
                    if (current.trim()) out.push(current.trim());
                    current = '';
                    continue;
                }
                current += ch;
            }
            if (current.trim()) out.push(current.trim());
            return out;
        }

        function findLastTopLevelScope(text) {
            let angle = 0;
            let paren = 0;
            let bracket = 0;
            let last = -1;
            for (let i = 0; i < text.length - 1; i++) {
                const ch = text[i];
                const next = text[i + 1];
                if (ch === '<') angle += 1;
                else if (ch === '>') angle = Math.max(0, angle - 1);
                else if (ch === '(') paren += 1;
                else if (ch === ')') paren = Math.max(0, paren - 1);
                else if (ch === '[') bracket += 1;
                else if (ch === ']') bracket = Math.max(0, bracket - 1);
                if (ch === ':' && next === ':' && angle === 0 && paren === 0 && bracket === 0) last = i;
            }
            return last;
        }

        function isCallableFragment(text) {
            const value = String(text || '').trim();
            if (!value) return false;
            if (/^(?:const|volatile|signed|unsigned|short|long|class|struct|enum|union)$/.test(value)) return false;
            if (/^operator\S+$/.test(value)) return true;
            if (/^[~A-Za-z_][A-Za-z0-9_]*$/.test(value)) return true;
            if (findLastTopLevelScope(value) >= 0) return true;
            return false;
        }

        function splitSignatureHead(head) {
            const text = String(head || '').trim();
            if (!text) return { returnType: '', callable: '' };
            const tokens = splitTopLevelWhitespace(text);
            for (let i = tokens.length - 1; i > 0; i--) {
                const candidateCallable = tokens.slice(i).join(' ');
                if (!isCallableFragment(candidateCallable)) continue;
                return {
                    returnType: tokens.slice(0, i).join(' ').trim(),
                    callable: candidateCallable.trim()
                };
            }
            if (findLastTopLevelScope(text) >= 0) {
                return { returnType: '', callable: text };
            }
            return { returnType: text, callable: '' };
        }

        function splitReturnTypeAndCallable(signatureHead) {
            return splitSignatureHead(signatureHead);
        }

        function templateDepth(text) {
            let depth = 0;
            let maxDepth = 0;
            const value = String(text || '');
            for (let i = 0; i < value.length; i++) {
                if (value[i] === '<') {
                    depth += 1;
                    maxDepth = Math.max(maxDepth, depth);
                } else if (value[i] === '>') {
                    depth = Math.max(0, depth - 1);
                }
            }
            return maxDepth;
        }

        function splitScope(label) {
            const parts = [];
            let current = '';
            let angle = 0;
            let paren = 0;
            for (let i = 0; i < label.length; i++) {
                const ch = label[i];
                const next = label[i + 1];
                if (ch === '<') angle += 1;
                else if (ch === '>') angle = Math.max(0, angle - 1);
                else if (ch === '(') paren += 1;
                else if (ch === ')') paren = Math.max(0, paren - 1);
                if (ch === ':' && next === ':' && angle === 0 && paren === 0) {
                    parts.push(current);
                    current = '';
                    i += 1;
                    continue;
                }
                current += ch;
            }
            if (current) parts.push(current);
            return parts.filter(Boolean);
        }

        function parseTemplateNode(text) {
            const value = (text || '').trim();
            if (!value) return null;
            const open = findTopLevelChar(value, '<');
            if (open < 0) return { label: value, path: splitScope(value), kind: 'leaf', args: [] };
            const close = findMatchingAngle(value, open);
            if (close < 0) return { label: value, path: splitScope(value), kind: 'leaf', args: [] };
            const label = value.slice(0, open).trim() || value;
            const inner = value.slice(open + 1, close).trim();
            return {
                label,
                path: splitScope(label),
                kind: 'template',
                args: splitTopLevel(inner).map(parseTemplateNode).filter(Boolean)
            };
        }

        function renderBinaryOverlapMetrics(sharedFunctions, knownPct, sharedObservations, observedPct, maxSharedFunctions, maxSharedObservations) {
            const fnWidth = maxSharedFunctions > 0 ? (Number(sharedFunctions || 0) / maxSharedFunctions) * 100 : 0;
            const obsWidth = maxSharedObservations > 0 ? (Number(sharedObservations || 0) / maxSharedObservations) * 100 : 0;
            return '<div class="timeline-metrics">'
                + '<div class="timeline-metric-row"><span class="timeline-metric-label">Known ' + fmt(sharedFunctions || 0) + ' // ' + Number(knownPct || 0).toFixed(1) + '%</span><div class="timeline-bar"><div class="timeline-bar-fill" style="width:' + fnWidth.toFixed(1) + '%"></div></div></div>'
                + '<div class="timeline-metric-row"><span class="timeline-metric-label">Observed ' + fmt(sharedObservations || 0) + ' // ' + Number(observedPct || 0).toFixed(1) + '%</span><div class="timeline-bar"><div class="timeline-bar-fill" style="width:' + obsWidth.toFixed(1) + '%"></div></div></div>'
                + '</div>';
        }

        function renderBinaryRelationshipRow(binary, options) {
            const opts = options || {};
            const label = opts.label || 'Related';
            const meta = opts.meta || (binary && binary.md5_hex ? binary.md5_hex : '');
            const actionHtml = opts.actionHtml || '<button class="result-action">open</button>';
            return '<div class="related-binary-row clickable" onclick="showBinaryDetail(\'' + esc(binary.md5_hex || '') + '\')">'
                + '<div class="related-binary-main"><div class="detail-label">' + esc(label) + '</div>' + renderBinaryTitle(binary) + '<div class="related-binary-meta">' + esc(meta) + '</div></div>'
                + renderBinaryOverlapMetrics(opts.sharedFunctions || 0, opts.knownPct || 0, opts.sharedObservations || 0, opts.observedPct || 0, opts.maxSharedFunctions || 1, opts.maxSharedObservations || 1)
                + '<div class="timeline-meta"><div class="detail-label">last seen ' + esc(fmtRelativeTs(binary.last_seen_ts)) + '</div><div class="binary-overlap-actions">' + actionHtml + '</div></div>'
                + '</div>';
        }

        function setBinaryGraphView(view) {
            currentBinaryGraphView = view === 'list' ? 'list' : 'graph';
            if (currentDetailKind === 'binary' && currentDetailData) renderBinaryDetail(currentDetailData);
        }

        function renderBinaryTimeline(items) {
            const rows = items || [];
            if (!rows.length) return '<div class="state-message"><div class="icon">::</div><h3>NO FAMILY TIMELINE</h3><p>Recency overlap data is not available yet.</p></div>';
            const maxSharedFunctions = Math.max(...rows.map(item => Number(item.shared_functions || 0)), 1);
            const maxSharedObservations = Math.max(...rows.map(item => Number(item.shared_observations || 0)), 1);
            return '<div class="timeline-stack">' + rows.map(item => {
                const binary = item.binary || {};
                return renderBinaryRelationshipRow(binary, {
                    label: item.is_root ? 'Root' : 'Related',
                    meta: binary.md5_hex || '',
                    sharedFunctions: item.shared_functions || 0,
                    knownPct: item.known_overlap_pct || 0,
                    sharedObservations: item.shared_observations || 0,
                    observedPct: item.observed_overlap_pct || 0,
                    maxSharedFunctions,
                    maxSharedObservations,
                    actionHtml: '<button class="result-action" onclick="event.stopPropagation();showBinaryDetail(\'' + esc(binary.md5_hex || '') + '\')">open</button>'
                });
            }).join('') + '</div>';
        }

        function renderBinaryGraph(graph, rootMd5) {
            const nodes = (graph && graph.nodes) ? graph.nodes : [];
            const edges = (graph && graph.edges) ? graph.edges : [];
            if (!nodes.length) return '<div class="state-message"><div class="icon">::</div><h3>NO GRAPH SIGNAL</h3><p>Overlap expansion did not surface related binaries yet.</p></div>';
            const width = 900;
            const height = 360;
            const rootIndex = nodes.findIndex(n => n.binary && n.binary.md5_hex === rootMd5);
            const rootNode = rootIndex >= 0 ? nodes[rootIndex] : nodes[0];
            const adjacency = new Map();
            edges.forEach(edge => {
                if (!adjacency.has(edge.source_md5)) adjacency.set(edge.source_md5, []);
                if (!adjacency.has(edge.target_md5)) adjacency.set(edge.target_md5, []);
                adjacency.get(edge.source_md5).push(edge.target_md5);
                adjacency.get(edge.target_md5).push(edge.source_md5);
            });
            const depthMap = new Map();
            depthMap.set(rootNode.binary.md5_hex, 0);
            const queue = [rootNode.binary.md5_hex];
            while (queue.length) {
                const cur = queue.shift();
                const curDepth = depthMap.get(cur) || 0;
                (adjacency.get(cur) || []).forEach(next => {
                    if (!depthMap.has(next)) {
                        depthMap.set(next, curDepth + 1);
                        queue.push(next);
                    }
                });
            }
            const layers = new Map();
            nodes.forEach(node => {
                const depth = depthMap.get(node.binary.md5_hex) || (node.binary.md5_hex === rootMd5 ? 0 : currentBinaryGraphDepth);
                if (!layers.has(depth)) layers.set(depth, []);
                layers.get(depth).push(node);
            });
            let html = '<div class="binary-graph"><div class="binary-graph-stage" style="transform:scale(' + currentBinaryGraphZoom.toFixed(2) + ')">';
            html += '<svg viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none">';
            const positions = new Map();
            const activeFocus = currentGraphFocusMd5 || '';
            const activeHover = currentGraphHoverMd5 || '';
            const activeNode = activeFocus || activeHover || '';
            const connected = new Set(activeFocus ? [activeFocus] : []);
            if (activeFocus) {
                edges.forEach(edge => {
                    if (edge.source_md5 === activeFocus) connected.add(edge.target_md5);
                    if (edge.target_md5 === activeFocus) connected.add(edge.source_md5);
                });
                connected.add(rootMd5);
            }
            [...layers.keys()].sort((a, b) => a - b).forEach(depth => {
                const layer = layers.get(depth) || [];
                layer.sort((a, b) => Number(b.binary.function_count || 0) - Number(a.binary.function_count || 0));
                const columns = Math.max(2, (currentBinaryGraphDepth || 2) + 2);
                const baseX = 120 + ((width - 240) * ((depth + 1) / columns));
                layer.forEach((node, idx) => {
                    const slot = idx + 1;
                    const y = (height / (layer.length + 1)) * slot;
                    const laneOffset = layer.length > 6 ? ((idx % 2) === 0 ? -42 : 42) : 0;
                    positions.set(node.binary.md5_hex, { x: baseX + laneOffset, y });
                });
            });
            edges.forEach(edge => {
                const a = positions.get(edge.source_md5);
                const b = positions.get(edge.target_md5);
                if (!a || !b) return;
                const alpha = Math.max(0.2, Math.min(0.85, Number(edge.shared_functions || 0) / 12));
                const highlighted = activeNode && (edge.source_md5 === activeNode || edge.target_md5 === activeNode);
                const dimmed = activeNode && !highlighted;
                html += '<line class="' + (highlighted ? 'highlighted' : (dimmed ? 'dimmed' : '')) + '" x1="' + a.x.toFixed(1) + '" y1="' + a.y.toFixed(1) + '" x2="' + b.x.toFixed(1) + '" y2="' + b.y.toFixed(1) + '" stroke="rgba(0,255,136,' + alpha.toFixed(2) + ')" stroke-width="' + Math.max(1, Math.min(5, Number(edge.shared_functions || 0) / 4)).toFixed(1) + '" />';
                if (activeFocus && highlighted) {
                    const mx = ((a.x + b.x) / 2).toFixed(1);
                    const my = ((a.y + b.y) / 2).toFixed(1);
                    html += '<text x="' + mx + '" y="' + my + '" fill="rgba(210,230,220,0.72)" font-size="10" text-anchor="middle">' + esc(String(edge.shared_functions || 0)) + '</text>';
                }
            });
            html += '</svg>';
            nodes.forEach(node => {
                const pos = positions.get(node.binary.md5_hex);
                if (!pos) return;
                const isHighlighted = activeNode && (node.binary.md5_hex === activeNode || connected.has(node.binary.md5_hex));
                const isDimmed = activeNode && !connected.has(node.binary.md5_hex);
                const isExpanded = node.binary.md5_hex === rootMd5 || node.binary.md5_hex === activeNode || (activeFocus && connected.has(node.binary.md5_hex));
                const isCompact = !isExpanded;
                html += '<div class="binary-graph-node' + (node.binary.md5_hex === rootMd5 ? ' root' : '') + (isHighlighted ? ' highlighted' : '') + (isDimmed ? ' dimmed' : '') + (isCompact ? ' compact' : '') + '" style="left:' + ((pos.x / width) * 100).toFixed(2) + '%; top:' + ((pos.y / height) * 100).toFixed(2) + '%" onmouseenter="setGraphHover(\'' + esc(node.binary.md5_hex) + '\')" onmouseleave="setGraphHover(\'\')" onclick="setGraphFocus(\'' + esc(node.binary.md5_hex) + '\')">'
                    + '<div class="name">' + esc(isCompact ? ('#' + (node.binary.short_id || '')) : shortenBinaryName(node.binary.basename || node.binary.display_name)) + '</div>'
                    + '<div class="meta">#' + esc(node.binary.short_id || '') + (isCompact ? '' : ' // ' + fmt(node.binary.function_count || 0) + ' fn') + '</div>'
                    + (isCompact ? '' : '<div class="meta">' + fmt(node.binary.obs_count || 0) + ' obs</div>')
                    + (isCompact ? '' : renderCoverageStrip(node.binary))
                    + (node.binary.md5_hex !== rootMd5 && !isCompact ? '<div class="binary-graph-node-actions"><button class="pagination-btn" onclick="event.stopPropagation();showBinaryDetail(\'' + esc(node.binary.md5_hex) + '\')">open</button></div>' : '')
                    + '</div>';
            });
            html += '</div></div>';
            return html;
        }

        function renderBinaryOverlapList(items, currentMd5) {
            const rows = items || [];
            if (!rows.length) return '<div class="state-message"><div class="icon">::</div><h3>NO RANKED OVERLAP</h3><p>No related binaries were derived from shared functions.</p></div>';
            const maxSharedFunctions = Math.max(...rows.map(edge => Number(edge.shared_functions || 0)), 1);
            const maxSharedObservations = Math.max(...rows.map(edge => Number(edge.shared_observations || 0)), 1);
            return '<div class="timeline-stack">' + rows.map(edge => renderBinaryRelationshipRow(edge.target || {}, {
                label: 'Related',
                meta: ((edge.target && edge.target.md5_hex) || ''),
                sharedFunctions: edge.shared_functions || 0,
                knownPct: edge.known_overlap_pct || 0,
                sharedObservations: edge.shared_observations || 0,
                observedPct: edge.observed_overlap_pct || 0,
                maxSharedFunctions,
                maxSharedObservations,
                actionHtml: '<button class="result-action" onclick="event.stopPropagation();loadBinaryCompare(\'' + esc((edge.target && edge.target.md5_hex) || '') + '\')">diff</button>'
            })).join('') + '</div>';
        }

        function renderBinaryComparePanel(compare) {
            if (!compare) return '';
            const activeLabel = compare.active_bucket || currentBinaryCompareMode || 'All';
            let html = '<div class="metadata-section"><div class="metadata-header"><span>Binary Diff</span><span class="badge nominal">COMPARE</span></div><div class="metadata-content">';
            html += '<div class="detail-grid" style="margin-bottom: var(--space-md);">';
            html += '<div class="detail-stat"><div class="label">Shared</div><div class="value">' + fmt(compare.shared_count || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Left Only</div><div class="value">' + fmt(compare.left_only_count || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Right Only</div><div class="value">' + fmt(compare.right_only_count || 0) + '</div></div>';
            html += '</div>';
            html += '<div class="compare-toolbar">';
            html += '<div class="compare-toolbar-row">';
            html += '<label class="compare-field"><span class="detail-label">Sample Size</span><input class="comment-search" type="number" min="1" max="100" value="' + esc(String(compare.sample_limit || currentBinaryCompareLimit || 18)) + '" onchange="setBinaryCompareLimit(this.value)"></label>';
            html += '<button class="pagination-btn" onclick="exportBinaryCompareReport()">Export JSON</button>';
            html += '<button class="pagination-btn" onclick="exportBinaryCompareMarkdown()">Export MD</button>';
            html += '<button class="pagination-btn" onclick="exportBinaryCompareCsv()">Export CSV</button>';
            html += '</div>';
            html += '<div class="compare-mode-switch">';
            [['all','All'], ['Shared','Shared'], ['Left Only','Left Only'], ['Right Only','Right Only'], ['Recent','Recent'], ['Metadata Rich','Highest Coverage'], ['Rare Symbols','Rare Symbols'], ['Freshest Drift','Freshest Drift']].forEach(entry => {
                const key = entry[0];
                const active = ((key === 'all' && currentBinaryCompareMode === 'all') || currentBinaryCompareMode === key) ? ' active' : '';
                html += '<button class="pagination-btn' + active + '" onclick="setBinaryCompareMode(\'' + key + '\')">' + esc(entry[1]) + '</button>';
            });
            html += '</div>';
            html += '<div class="preset-note">' + esc(comparePresetDescription(activeLabel === 'All' ? 'all' : activeLabel)) + '</div>';
            html += '<div class="compare-search-row">';
            html += '<label class="compare-field" style="min-width:240px;"><span class="detail-label">Filter Bucket</span><input class="comment-search" type="text" value="' + esc(currentBinaryCompareQuery || '') + '" oninput="setBinaryCompareQuery(this.value)" placeholder="search compare buckets"></label>';
            html += '</div>';
            html += '</div>';
            html += '<div class="binary-compare-grid">';
            html += '<div class="coverage-card"><div class="label">LEFT</div><div class="value">' + esc(renderBinaryName(compare.left)) + '</div></div>';
            html += '<div class="coverage-card"><div class="label">RIGHT</div><div class="value">' + esc(renderBinaryName(compare.right)) + '</div></div>';
            html += '</div>';
            html += '<div class="compare-list-grid">';
            const groups = currentBinaryCompareMode === 'all'
                ? [['Shared', compare.shared], ['Left Only', compare.left_only], ['Right Only', compare.right_only]]
                : [[compare.active_bucket || currentBinaryCompareMode, compare.active_bucket_items || []]];
            groups.forEach(group => {
                const pageItems = group[1] || [];
                html += '<div class="compare-list-column"><div class="detail-label">' + esc(group[0]) + '</div>';
                if (!pageItems.length) {
                    html += '<div class="detail-value">-</div>';
                } else {
                    pageItems.forEach(item => {
                        html += '<div class="compare-item-row" onclick="showFunctionDetail(\'' + esc(item.key_hex) + '\')"><div class="compare-item-main"><div class="compare-item-name">' + esc(item.name) + '</div><div class="compare-item-meta">RARITY ' + fmt(item.rarity_score || 0) + ' // COVER ' + fmt(item.richness_score || 0) + '</div></div><div class="compare-item-age">' + esc(fmtRelativeTs(item.ts)) + '</div></div>';
                    });
                    const totalPages = Number(compare.active_bucket_total_pages || 1);
                    const page = Number(compare.active_bucket_page || 1);
                    if (currentBinaryCompareMode !== 'all' && totalPages > 1) {
                        html += '<div class="pagination">';
                        html += '<button class="pagination-btn" onclick="setBinaryComparePage(' + (page - 1) + ')"' + (page <= 1 ? ' disabled' : '') + '>&lt;&lt; PREV</button>';
                        html += '<span class="pagination-info">PAGE <span class="accent">' + page + '</span> OF <span class="accent">' + totalPages + '</span></span>';
                        html += '<button class="pagination-btn" onclick="setBinaryComparePage(' + (page + 1) + ')"' + (page >= totalPages ? ' disabled' : '') + '>NEXT &gt;&gt;</button>';
                        html += '</div>';
                    }
                }
                html += '</div>';
            });
            html += '</div></div></div>';
            return html;
        }

        function renderBinaryCompareView() {
            const compare = currentBinaryCompareData;
            if (!compare) {
                el.binaryCompareTitle.textContent = '-';
                el.binaryCompareBody.innerHTML = '<div class="state-message"><div class="icon">::</div><h3>NO COMPARE LOADED</h3><p>Select a related binary or graph node to start a diff.</p></div>';
                return;
            }
            if (currentBinaryComparePage < 1) currentBinaryComparePage = 1;
            el.binaryCompareTitle.textContent = (compare.left && compare.left.display_name ? compare.left.display_name : 'left') + ' VS ' + (compare.right && compare.right.display_name ? compare.right.display_name : 'right');
            let html = '<div class="detail-layout"><div class="detail-main">' + renderBinaryComparePanel(compare) + '</div></div>';
            el.binaryCompareBody.innerHTML = html;
        }

        function renderBinaryDetail(data) {
            if (data.error) {
                el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>ERROR</h3><p>' + esc(data.error) + '</p></div>';
                return;
            }

            currentDetailData = data;
            currentBinaryMd5 = data.binary && data.binary.md5_hex ? data.binary.md5_hex : currentBinaryMd5;
            el.modalKey.textContent = currentBinaryMd5 || '';
            if (currentBinaryCompareData && (!currentBinaryCompareData.left || currentBinaryCompareData.left.md5_hex !== currentBinaryMd5)) {
                currentBinaryCompareData = null;
            }

            const binary = data.binary || {};
            const facets = data.facets || {};
            const graph = data.graph || { nodes: [], edges: [] };
            const timeline = data.timeline || [];
            const fnPage = data.functions || { results: [], total: 0, page: 1, total_pages: 1 };
            let html = '<div class="detail-layout"><div class="detail-main">';
            html += '<div class="detail-section"><div class="detail-label">Binary</div><div class="detail-value accent">' + esc(renderBinaryName(binary) || currentBinaryMd5 || '') + '</div></div>';
            html += '<div class="detail-section"><div class="detail-label">MD5</div><div class="detail-value mono">' + esc(binary.md5_hex || '') + '</div></div>';
            html += '<div class="detail-grid">';
            html += '<div class="detail-stat"><div class="label">Functions</div><div class="value">' + fmt(binary.function_count || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Typed Functions</div><div class="value">' + fmt(binary.typed_functions || facets.typed_functions || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Observations</div><div class="value">' + fmt(binary.obs_count || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">First Seen</div><div class="value">' + esc(fmtRelativeTs(binary.first_seen_ts)) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Last Seen</div><div class="value">' + esc(fmtRelativeTs(binary.last_seen_ts)) + '</div></div>';
            html += '</div>';

            html += '<div class="detail-section"><div class="detail-label">Observed Function Versions</div><div class="detail-value">' + fmt(binary.version_count || 0) + '</div><div class="detail-note">Distinct function-metadata version ids seen inside this binary; this is not a binary release count.</div></div>';

            html += '<div class="metadata-section"><div class="metadata-header"><span>Coverage Profile</span><span class="badge nominal">FACETS</span></div><div class="metadata-content"><div class="binary-coverage-grid">';
            html += renderBinaryFacetCard('Typed', facets.typed_functions || 0, facets.function_count || binary.function_count || 0);
            html += renderBinaryFacetCard('Frames', facets.framed_functions || 0, facets.function_count || binary.function_count || 0);
            html += renderBinaryFacetCard('Comments', facets.commented_functions || 0, facets.function_count || binary.function_count || 0);
            html += renderBinaryFacetCard('Switches', facets.switch_functions || 0, facets.function_count || binary.function_count || 0);
            html += renderBinaryFacetCard('Partial Parse', facets.parse_partial_functions || 0, facets.function_count || binary.function_count || 0);
            html += renderBinaryFacetCard('Demangled', facets.demangled_functions || 0, facets.function_count || binary.function_count || 0);
            html += '</div></div></div>';

            html += '<div class="metadata-section"><div class="metadata-header"><span>Related Binaries</span><span class="badge nominal">OVERLAP</span></div><div class="metadata-content">';
            html += '<div class="binary-graph-toolbar">';
            html += '<label class="binary-graph-field"><span class="detail-label">Depth</span><input class="comment-search" type="number" min="1" max="3" value="' + esc(String(currentBinaryGraphDepth)) + '" onchange="loadBinaryGraph(this.value, ' + currentBinaryGraphLimit + ')"></label>';
            html += '<label class="binary-graph-field"><span class="detail-label">Branch</span><input class="comment-search" type="number" min="1" max="16" value="' + esc(String(currentBinaryGraphLimit)) + '" onchange="loadBinaryGraph(' + currentBinaryGraphDepth + ', this.value)"></label>';
            html += '<div class="binary-graph-hint">Known = shared recognized functions. Observed = shared observed hashes/signals. Graph view is temporarily disabled.</div>';
            html += '</div>';
            // Graph view is temporarily disabled until the interaction model is improved.
            html += renderBinaryOverlapList(data.related || [], binary.md5_hex || currentBinaryMd5 || '');
            html += '</div></div>';

            html += '<div class="metadata-section"><div class="metadata-header"><span>Family Timeline</span><span class="badge nominal">RECENCY</span></div><div class="metadata-content">';
            html += renderBinaryTimeline(timeline);
            html += '</div></div>';

            html += '<div class="metadata-section"><div class="metadata-header"><span>Functions In Binary</span><span class="badge">' + fmt(fnPage.total || 0) + ' TOTAL</span></div><div class="metadata-content">';
            if (!fnPage.results || fnPage.results.length === 0) {
                html += '<div class="state-message"><div class="icon">[ ]</div><h3>NO FUNCTIONS INDEXED</h3><p>No associated functions were recovered for this binary.</p></div>';
            } else {
                fnPage.results.forEach(hit => {
                    const bins = (hit.binaries || []).map(b => '<span class="bin-tag clickable" onclick="event.stopPropagation();showBinaryDetail(\'' + esc(b.md5_hex) + '\')">' + esc(b.basename) + '<span class="accent">#' + esc(b.short_id) + '</span></span>').join('');
                    const displayNameHtml = renderCompactSignatureText(hit.func_name_demangled || hit.func_name, false);
                    html += '<div class="result-item clickable" onclick="showFunctionDetail(\'' + esc(hit.key_hex) + '\')">'
                        + '<div class="result-main"><div class="result-func">' + displayNameHtml + '</div><div class="result-key"><span class="result-key-copy" onclick="event.stopPropagation();copyResultKey(\'' + esc(hit.key_hex) + '\')">KEY ' + esc(hit.key_hex) + '</span><span class="result-age">' + esc(fmtRelativeTs(hit.ts)) + '</span></div><div class="result-bins">' + bins + '</div></div>'
                        + '<div class="result-meta"><span class="score-badge">OBS ' + fmt(hit.score || 0) + '</span></div>'
                        + '</div>';
                });
                if ((fnPage.total_pages || 1) > 1) {
                    html += '<div class="pagination">';
                    html += '<button class="pagination-btn" onclick="loadBinaryFunctionsPage(\'' + esc(binary.md5_hex || currentBinaryMd5 || '') + '\',' + ((fnPage.page || 1) - 1) + ')"' + ((fnPage.page || 1) <= 1 ? ' disabled' : '') + '>&lt;&lt; PREV</button>';
                    html += '<span class="pagination-info">PAGE <span class="accent">' + (fnPage.page || 1) + '</span> OF <span class="accent">' + (fnPage.total_pages || 1) + '</span></span>';
                    html += '<button class="pagination-btn" onclick="loadBinaryFunctionsPage(\'' + esc(binary.md5_hex || currentBinaryMd5 || '') + '\',' + ((fnPage.page || 1) + 1) + ')"' + ((fnPage.page || 1) >= (fnPage.total_pages || 1) ? ' disabled' : '') + '>NEXT &gt;&gt;</button>';
                    html += '</div>';
                }
            }
            html += '</div></div>';
            html += '</div></div>';
            el.modalBody.innerHTML = html;
        }

        function renderFunctionDetail(data) {
            if (data.error) {
                el.modalBody.innerHTML = '<div class="state-message"><div class="icon">!</div><h3>ERROR</h3><p>' + esc(data.error) + '</p></div>';
                return;
            }

            currentDetailData = data;
            currentDetailKeyHex = data.key_hex || currentDetailKeyHex;
            ensureSemanticNeighborsLoaded(currentDetailKeyHex);

            const m = data.metadata || {};
            const parseBadge = (m.errors && m.errors.length > 0) ? 'PARTIAL' : 'PARSED';

            const sections = [
                { id: 'section-overview', label: 'Overview' },
            ];
            if (m.fcmt || m.frptcmt || m.vd_elapsed !== null) sections.push({ id: 'section-attrs', label: 'Attributes' });
            if (m.type_parts) sections.push({ id: 'section-type', label: 'Type' });
            if (m.frame_desc) sections.push({ id: 'section-frame', label: 'Frame' });
            if (m.control_flow && ((m.control_flow.switches || []).length > 0 || (m.control_flow.jumptables || []).length > 0)) sections.push({ id: 'section-controlflow', label: 'Switches' });
            if ((m.raw_chunk_count || (m.raw_chunks || []).length || (m.extra_cmts || []).length) > 0 || m.user_stkpnts || m.ops || m.ops_ex) sections.push({ id: 'section-semantic', label: 'Semantic' });
            sections.push({ id: 'section-neighbors', label: 'Neighbors' });
            if (((m.insn_cmts || []).length + (m.rpt_insn_cmts || []).length) > 0) sections.push({ id: 'section-comments', label: 'Comments' });
            if ((m.errors || []).length > 0) sections.push({ id: 'section-errors', label: 'Errors' });

            let html = '<div class="detail-layout">';
            html += '<div class="detail-nav">';
            const activeSectionId = pendingDetailSection || currentDetailSection || sections[0].id;
            sections.forEach((s, i) => {
                html += '<button data-target="' + s.id + '" class="' + (s.id === activeSectionId || (i === 0 && !activeSectionId) ? 'active' : '') + '" onclick="activateDetailSection(\'' + s.id + '\');">' + esc(s.label) + '</button>';
            });
            html += '</div><div class="detail-main">';

            // Function name
            const overviewName = renderOverviewFunctionName(data, m);
            html += '<div class="detail-section detail-anchor" id="section-overview"><div class="detail-label">Function Name</div><div class="detail-name-stack">';
            html += '<div class="detail-value accent">' + overviewName + '</div>';
            html += '<div class="detail-name-meta">';
            if (data.lang) {
                html += '<span class="lang-badge">' + esc(String(data.lang).toUpperCase()) + '</span>';
            }
            html += '<span class="version-badge age">' + esc(fmtRelativeTs(data.ts)) + '</span>';
            html += '</div>';
            if (data.raw_name) {
                html += '<div class="result-mangled" title="Stored raw symbol name">' + esc(data.raw_name) + '</div>';
            }
            html += '</div></div>';

            // Key
            html += '<div class="detail-section"><div class="detail-label">Function Key</div><div class="detail-value mono">' + esc(data.key_hex) + '</div></div>';

            // Stats grid
            html += '<div class="detail-grid">';
            html += '<div class="detail-stat"><div class="label">Data Size</div><div class="value">' + fmtBytes(data.data_size || 0) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Metadata State</div><div class="value">' + esc(parseBadge) + '</div></div>';
            html += '<div class="detail-stat"><div class="label">Age</div><div class="value">' + esc(fmtRelativeTs(data.ts)) + '</div></div>';
            html += '</div>';

            // Binary names
            if (data.binaries && data.binaries.length > 0) {
                html += '<div class="detail-section"><div class="detail-label">Associated Binaries</div><div class="result-bins">';
                data.binaries.forEach(b => { html += '<span class="bin-tag clickable" onclick="openBinaryFromFunction(\'' + esc(b.md5_hex) + '\', \'' + encodeURIComponent(b.basename) + '\')">' + esc(b.basename) + '<span class="accent">#' + esc(b.short_id) + '</span></span>'; });
                html += '</div></div>';
            } else if (data.binary_names && data.binary_names.length > 0) {
                html += '<div class="detail-section"><div class="detail-label">Associated Binaries</div><div class="result-bins">';
                data.binary_names.forEach(b => { html += '<span class="bin-tag">' + esc(b) + '</span>'; });
                html += '</div></div>';
            }

            // Metadata sections
            if (m) {
                // Function Comments (MDK_FCMT / MDK_FRPTCMT)
                if (m.fcmt || m.frptcmt || m.vd_elapsed !== null) {
                    html += '<div class="metadata-section detail-anchor" id="section-attrs"><div class="metadata-header"><span>Function Attributes</span></div><div class="metadata-content" style="display: flex; flex-direction: column; gap: var(--space-md);">';
                    
                    if (m.vd_elapsed !== null && m.vd_elapsed !== undefined) {
                        html += '<div class="detail-stat" style="width: max-content;"><div class="label">Decompilation Time</div><div class="value">' + m.vd_elapsed + ' seconds</div></div>';
                    }

                    if (m.fcmt) {
                        html += '<div class="detail-section"><div class="detail-label">Regular Comment</div><div class="detail-value mono" style="white-space: pre-wrap;">' + esc(m.fcmt) + '</div></div>';
                    }

                    if (m.frptcmt) {
                        html += '<div class="detail-section"><div class="detail-label">Repeatable Comment</div><div class="detail-value mono" style="white-space: pre-wrap;">' + esc(m.frptcmt) + '</div></div>';
                    }
                    
                    html += '</div></div>';
                }

                // Type Parts (MDK_TYPE)
                if (m.type_parts) {
                    html += '<div class="metadata-section detail-anchor" id="section-type"><div class="metadata-header"><span>MDK_TYPE Data</span><span class="badge nominal">PRESENT</span></div><div class="metadata-content">';
                    html += renderTypeSignature(m.type_parts);
                    html += '</div></div>';
                }

                // Frame Desc (MDK_FRAME_DESC)
                if (m.frame_desc) {
                    const fd = m.frame_desc;
                    html += '<div class="metadata-section detail-anchor" id="section-frame"><div class="metadata-header"><span>Frame Descriptor</span><span class="badge">' + (fd.members ? fd.members.length : 0) + ' MEMBERS</span></div><div class="metadata-content">';
                    
                    html += '<div class="detail-grid" style="margin-bottom: var(--space-md);">';
                    html += '<div class="detail-stat"><div class="label">Frame Size</div><div class="value">0x' + (fd.frsize || 0).toString(16) + '</div></div>';
                    html += '<div class="detail-stat"><div class="label">Arg Size</div><div class="value">0x' + (fd.argsize || 0).toString(16) + '</div></div>';
                    html += '<div class="detail-stat"><div class="label">Saved Regs</div><div class="value">0x' + (fd.frregs || 0).toString(16) + '</div></div>';
                    html += '</div>';

                    html += renderFrameDiagnostics(fd);
                    html += renderFrameDescriptor(fd);
                    html += '</div></div>';
                }

                if (m.control_flow && ((m.control_flow.switches || []).length > 0 || (m.control_flow.jumptables || []).length > 0)) {
                    html += '<div class="metadata-section detail-anchor" id="section-controlflow"><div class="metadata-header"><span>Switch / Jumptable Analysis</span><span class="badge nominal">CONTROL FLOW</span></div><div class="metadata-content">';
                    html += renderControlFlowMetadata(m.control_flow);
                    html += '</div></div>';
                }

                const semanticSection = renderSemanticMetadata(m);
                if (semanticSection) {
                    html += semanticSection;
                }

                html += renderSemanticNeighborSection();

                // Instruction Comments Timeline
                const regCount = Array.isArray(m.insn_cmts) ? m.insn_cmts.length : 0;
                const rptCount = Array.isArray(m.rpt_insn_cmts) ? m.rpt_insn_cmts.length : 0;
                const totalCommentCount = regCount + rptCount;
                if (totalCommentCount > 0) {
                    html += '<div class="metadata-section detail-anchor" id="section-comments"><div class="metadata-header"><span>Instruction Comment Timeline</span><span class="badge">' + totalCommentCount + '</span></div><div class="metadata-content">';
                    html += renderInstructionCommentTimeline(m.insn_cmts, m.rpt_insn_cmts, m.control_flow);
                    html += '</div></div>';
                }

                // Raw stats
                if (m.errors && m.errors.length > 0) {
                    html += '<div class="state-message detail-anchor" id="section-errors" style="margin-top: var(--space-md); border-color: var(--state-warning); background: rgba(255, 102, 0, 0.1);"><div class="icon" style="color: var(--state-warning);">!</div><h3 style="color: var(--state-warning);">PARSE ERRORS</h3><ul style="text-align: left; margin-top: var(--space-sm);">';
                    m.errors.forEach(err => {
                        html += '<li>' + esc(err) + '</li>';
                    });
                    html += '</ul></div>';
                }
            }

            html += '</div></div>';
            el.modalBody.innerHTML = html;
            if (pendingDetailSection) {
                activateDetailSection(pendingDetailSection, false, false);
                pendingDetailSection = null;
            } else if (!currentDetailSection) {
                currentDetailSection = 'section-overview';
                setActiveDetailNav(currentDetailSection, false);
            } else {
                setActiveDetailNav(currentDetailSection, false);
            }
        }
    </script>
</body>
</html>
"#;
