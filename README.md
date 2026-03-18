Automated SOC PROJECT

This project implements an end-to-end automated SOC triage pipeline using:
Wazuh → alert generation
TheHive → case & observable management
Cortex → enrichment via analyzers
Google Gemini → AI-based decision engine

The system operates continuously and performs case-level analysis 
Wazuh generates alerts
TheHive creates cases + observables
Script detects observables tagged to-analyze
Cortex analyzers enrich each observable
Gemini evaluates the entire case
Case is updated with:
AI decision
confidence
explanation
