import json
import os

def load_ground_truth(file_path):
    if not os.path.exists(file_path):
        return set()
    with open(file_path, 'r') as f:
        data = json.load(f)
    return set((item['file'], item['line']) for item in data)

def parse_semgrep(file_path):
    findings = set()
    if not os.path.exists(file_path):
        return findings
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    for loc in result.get('locations', []):
                        phys = loc.get('physicalLocation', {})
                        uri = phys.get('artifactLocation', {}).get('uri', '').replace('./', '')
                        line = phys.get('region', {}).get('startLine')
                        if uri and line:
                            findings.add((uri, line))
    except Exception as e:
        print(f"Error parsing Semgrep: {e}")
    return findings

def parse_horusec(file_path):
    findings = set()
    if not os.path.exists(file_path):
        return findings
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            vulns = data.get('analysisVulnerabilities', [])
            for item in vulns:
                vuln = item.get('vulnerability', {})
                file_name = vuln.get('file', '').replace('./', '')
                line = int(vuln.get('line', 0))
                if file_name and line > 0:
                    findings.add((file_name, line))
    except Exception as e:
        print(f"Error parsing Horusec: {e}")
    return findings

def parse_sonarqube(file_path):
    findings = set()
    if not os.path.exists(file_path):
        return findings
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            # Mendukung format API SonarQube/SonarCloud JSON maupun SARIF SonarScanner
            if 'issues' in data:
                for issue in data.get('issues', []):
                    component = issue.get('component', '').split(':')[-1].replace('./', '')
                    line = issue.get('line')
                    if component and line:
                        findings.add((component, line))
            elif 'runs' in data:
                for run in data.get('runs', []):
                    for result in run.get('results', []):
                        for loc in result.get('locations', []):
                            phys = loc.get('physicalLocation', {})
                            uri = phys.get('artifactLocation', {}).get('uri', '').replace('./', '')
                            line = phys.get('region', {}).get('startLine')
                            if uri and line:
                                findings.add((uri, line))
    except Exception as e:
        print(f"Error parsing SonarQube: {e}")
    return findings

def evaluate_scenario(name, detected_set, gt_set):
    tp = len(detected_set.intersection(gt_set))
    fp = len(detected_set - gt_set)
    fn = len(gt_set - detected_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        'name': name,
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'precision': round(precision * 100, 2),
        'recall': round(recall * 100, 2),
        'f1': round(f1 * 100, 2)
    }

def main():
    gt_set = load_ground_truth('ground_truth.json')

    # 1. Parsing hasil masing-masing tool
    semgrep_set = parse_semgrep('semgrep-results.json')
    horusec_set = parse_horusec('horusec-results.json')
    sonar_set = parse_sonarqube('sonarqube-results.json')

    results = []

    # --- SKENARIO A: INDIVIDUAL TOOLS ---
    results.append(evaluate_scenario("Skenario A - Semgrep", semgrep_set, gt_set))
    results.append(evaluate_scenario("Skenario A - Horusec", horusec_set, gt_set))
    results.append(evaluate_scenario("Skenario A - SonarQube", sonar_set, gt_set))

    # --- SKENARIO B: KOMBINASI 2 TOOLS (UNION / OR) ---
    semgrep_horusec = semgrep_set.union(horusec_set)
    semgrep_sonar = semgrep_set.union(sonar_set)
    horusec_sonar = horusec_set.union(sonar_set)

    results.append(evaluate_scenario("Skenario B - Semgrep + Horusec", semgrep_horusec, gt_set))
    results.append(evaluate_scenario("Skenario B - Semgrep + SonarQube", semgrep_sonar, gt_set))
    results.append(evaluate_scenario("Skenario B - Horusec + SonarQube", horusec_sonar, gt_set))

    # --- SKENARIO C: KOMBINASI 3 TOOLS (UNION / OR) ---
    all_three = semgrep_set.union(horusec_set).union(sonar_set)
    results.append(evaluate_scenario("Skenario C - Semgrep + Horusec + SonarQube", all_three, gt_set))

    # Cetak ringkasan ke Console & GitHub Job Summary
    summary_md = f"### 📊 Ringkasan Evaluasi Kinerja SAST\n"
    summary_md += f"**Total Ground Truth Vulnerabilities:** {len(gt_set)}\n\n"
    summary_md += "| Skenario Pengujian | TP | FP | FN | Precision (%) | Recall (%) | F1-Score (%) |\n"
    summary_md += "| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n"

    for r in results:
        summary_md += f"| **{r['name']}** | {r['tp']} | {r['fp']} | {r['fn']} | {r['precision']}% | {r['recall']}% | **{r['f1']}%** |\n"

    print(summary_md)

    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(summary_md)

if __name__ == '__main__':
    main()
