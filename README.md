# PhishGuard-Simple-Phishing-Detector
Client-side phishing URL analyzer with heuristics, lookalike detection, UX polish, and local scan history, no backend required.

A lightweight, responsive web app (single index.html) that analyzes URLs for common phishing indicators perfect for beginners who want a practical security project to demo in their portfolio.

Why this project?
Phishing is still the #1 user-targeted attack vector. PhishGuard teaches core security heuristics (URL parsing, lookalike domains, punycode, TLS checks) while showing clean UI/UX and local persistence a great bridge between design and cybersecurity.

Features:
Heuristic checks: @ symbol, IP domains, long URLs, many subdomains, hyphens, suspicious chars
Lookalike domain detection + punycode (xn--)
Keyword scanning (login, verify, secure, bank, etc.)
Missing HTTPS and simple SSL/certificate info (client-side)
Redirect-chain detection (follow up to 3 redirects)
Threat score bar + clear verdicts: Safe / Suspicious / Likely Phishing
History of last 5 scans saved in localStorage
Dark / Light mode, animated results, polished UI
Single-file, zero-deps: run locally by opening index.html
Tech
HTML, CSS, JavaScript (ES6+)
No backend — runs fully in the browser

Quick start:
Clone repo: git clone https://github.com/Srijanstha117/PhishGuard-Simple-Phishing-Detector.git
Open index.html in your browser.
Paste a URL and click Analyze.
