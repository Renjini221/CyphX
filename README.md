# CyphX


## CyphX is a web-based cybersecurity tool that analyzes URLs for potential threats using Google Safe Browsing API and custom risk detection logic. It classifies websites as Safe, Suspicious, or Dangerous in real-time.

## Working
<img width="833" height="512" alt="image" src="https://github.com/user-attachments/assets/af05b79a-2953-493b-963d-091f042678f2" />
## Risk scoring

| Signal | Score |
|--------|-------|
| Brand name in domain | +3 |
| Similar to known brand (>60%) | +3 |
| Sus keywords (login, secure, verify) | +1 |
| Domain > 20 chars | +1 |
| 3+ digits in domain | +1 |
| Domain changed after redirect | +2 |
| 3+ redirects | +1 |
| DNS unresolvable | +2 |
| Single IP | +1 |
| SSL invalid or self-signed | +2 |
| SSL expiring in <10 days | +2 |

Score >= 2 gets flagged as suspicious before hitting Safe Browsing and AI.

## Results

- Safe — passed all checks
- Suspicious — one or more signals triggered
- Danger — flagged by GSB or AI

## Stack

- Backend — Python, Flask
- Frontend — Vanilla HTML/CSS/JS
- APIs — Google Safe Browsing v4, WhoisJSON, OpenRouter (GPT-4o-mini

## AI Decleration

-debugged and styled by Claude
