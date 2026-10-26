import json
import os

def load_ground_truth(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as f:
        data = json.load(f)
    # Ambil baris target rentan dari ground_truth
    return set((item['file'], item['line']) for item in data)

def calculate_metrics(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return precision, recall, f1

def main():
    gt_set = load_ground_truth('ground_truth.json')
    print(f"Total Ground Truth Vulnerabilities: {len(gt_set)}")
    print("=" * 50)
    # Lanjutan logika pencocokan SARIF/JSON akan dieksekusi di sini

if __name__ == '__main__':
    main()