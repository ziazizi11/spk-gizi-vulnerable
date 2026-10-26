import json
import os

def load_ground_truth(file_path):
    if not os.path.exists(file_path):
        print(f"[DEBUG] File {file_path} TIDAK DITEMUKAN!")
        return set()
    with open(file_path, 'r') as f:
        data = json.load(f)
    return set((os.path.basename(item['file']), int(item['line'])) for item in data)

def parse_semgrep(file_path):
    findings = set()
    if not os.path.exists(file_path):
        print(f"[DEBUG] {file_path} TIDAK DITEMUKAN!")
        return findings
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    for loc in result.get('locations', []):
                        phys = loc.get('physicalLocation', {})
                        uri = phys.get('artifactLocation', {}).get('uri', '')
                        line = phys.get('region', {}).get('startLine')
                        if uri and line:
                            findings.add((os.path.basename(uri), int(line)))
    except Exception as e:
        print(f"Error parsing Semgrep: {e}")
    print(f"[DEBUG] Semgrep Raw Findings: {len(findings)}")
    return findings

def parse_horusec(file_path):
    findings = set()
    if not os.path.exists(file_path):
        print(f"[DEBUG] {file_path} TIDAK DITEMUKAN!")
        return findings
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            vulns = data.get('analysisVulnerabilities', [])
            if not vulns and isinstance(data, list):
                vulns = data
            for item in vulns:
                vuln = item.get('vulnerability', item)
                file_name = vuln.get('file', '')
                line = vuln.get('line')
                if file_name and line:
                    findings.add((os.path.basename(file_name), int(line)))
    except Exception as e:
        print(f"Error parsing Horusec: {e}")
    print(f"[DEBUG] Horusec Raw Findings: {len(findings)}")
    return findings

def parse_bandit(file_path):
    findings = set()
    if not os.path.exists(file_path):
        print(f"[DEBUG] {file_path} TIDAK DITEMUKAN!")
        return findings
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            results = data.get('results', [])
            for result in results:
                file_name = result.get('filename', '')
                line = result.get('line_number')
                if file_name and line:
                    findings.add((os.path.basename(file_name), int(line)))
    except Exception as e:
        print(f"Error parsing Bandit: {e}")
    print(f"[DEBUG] Bandit Raw Findings: {len(findings)}")
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
    print(f"[DEBUG] Ground Truth Target Count: {len(gt_set)}")

    semgrep_set = parse_semgrep('semgrep-results.json')
    horusec_set = parse_horusec('horusec-results.json')
    bandit_set = parse_bandit('bandit-results.json')

    results = []
    results.append(evaluate_scenario("Skenario A - Semgrep", semgrep_set, gt_set))
    results.append(evaluate_scenario("Skenario A - Horusec", horusec_set, gt_set))
    results.append(evaluate_scenario("Skenario A - Bandit", bandit_set, gt_set))

    results.append(evaluate_scenario("Skenario B - Semgrep + Horusec", semgrep_set.union(horusec_set), gt_set))
    results.append(evaluate_scenario("Skenario B - Semgrep + Bandit", semgrep_set.union(bandit_set), gt_set))
    results.append(evaluate_scenario("Skenario B - Horusec + Bandit", horusec_set.union(bandit_set), gt_set))

    results.append(evaluate_scenario("Skenario C - Semgrep + Horusec + Bandit", semgrep_set.union(horusec_set).union(bandit_set), gt_set))

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
