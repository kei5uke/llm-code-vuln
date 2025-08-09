# llm-code-vuln
This repository contains the implementation and experimental code for my master's thesis: "Evaluating and Fine-Tuning Large Language Models for Code Vulnerability Detection Across Programming Languages and Code Granularities."  
The thesis investigates the ability of Microsoft’s Phi-4 to detect code vulnerabilities using the CVEfixes dataset.  
Our experiments focus on evaluating performance across different programming languages, input granularities, and prompting strategies.

## Experiment Settings
- Dataset
  - 6 programming languages: `PHP`, `JavaScript`, `Java`, `TypeScript`, `Ruby`, `Python`
  - 4 major CWE types: `CWE-79`, `CWE-89`, `CWE-434`, `CWE-352` + non-vulnerable code
- Prompting Strategies
  - Zero-shot
  - Few-shot
  - Chain-of-thought
- Evaluation Levels
  - File-level code
  - Function-level code

## Discovery
- Programming Language Influence: Detection performance varies by language due to language-specific characteristics.
- Input Granularity: File-level analysis provides broader context, improving detection of vulnerabilities across multiple functions and reducing false positives.
- Benefits of Fine-Tuning: Improves classification performance across prompt strategies and input configurations, lowering both false positive and false negative rates.

## Setup
1. Clone the repository
```bash
git clone https://github.com/kei5uke/llm-code-vuln.git
cd llm-code-vuln
```
2. Install dependencies
```bash
pip install -r requirements.txt
```
3. Prepare the dataset
Download the [CVEfixes](https://github.com/secureIT-project/CVEfixes) database.  
Place it in the dataset directory.  
Set up your SQLite environment accordingly.  
