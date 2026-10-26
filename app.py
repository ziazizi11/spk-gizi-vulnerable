import os
import sqlite3
import pickle
import base64
from flask import Flask, render_template, request, render_template_string, redirect, jsonify

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Secret Key (CWE-798)
app.secret_key = "super_secret_hardcoded_key_12345"

def get_db_connection():
    conn = sqlite3.connect('gizi.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS food_recommendations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            calories INTEGER NOT NULL,
            protein REAL NOT NULL DEFAULT 0,
            fat REAL NOT NULL DEFAULT 0
        )
    ''')
    # Isi data dummy jika kosong
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM food_recommendations")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO food_recommendations (name, category, calories, protein, fat) VALUES (?, ?, ?, ?, ?)",
            [
                ('Dada Ayam Panggang', 'Defisit', 165, 31.0, 3.6),
                ('Nasi Merah & Tempe', 'Defisit', 250, 12.0, 5.0),
                ('Alpukat & Telur Rebus', 'Maintenance', 300, 9.0, 22.0),
                ('Susu Full Cream & Pisang', 'Surplus', 450, 11.0, 10.0),
                ('Ikan Salmon Panggang', 'Defisit', 208, 20.0, 13.0),
                ('Daging Sapi Rendang', 'Surplus', 390, 26.0, 21.0),
                ('Salad Sayur & Tahu', 'Defisit', 130, 8.0, 4.0),
                ('Oatmeal & Pisang', 'Maintenance', 220, 7.0, 3.5)
            ]
        )
        conn.commit()
    conn.close()

init_db()

def calculate_saw_ranking(foods, weights=None):
    """
    Menghitung perangkingan makanan menggunakan metode Simple Additive Weighting (SAW).
    Kriteria:
    - Kalori (Cost): semakin rendah kalori semakin baik untuk efisiensi diet defisit
    - Protein (Benefit): semakin tinggi protein semakin baik untuk asupan gizi
    - Lemak (Cost): semakin rendah lemak semakin baik
    """
    if not foods:
        return []
    
    if weights is None:
        weights = {'calories': 0.3, 'protein': 0.5, 'fat': 0.2}

    min_cal = min(f['calories'] for f in foods)
    max_protein = max(f['protein'] for f in foods)
    min_fat = min(f['fat'] for f in foods)

    ranked_results = []
    for food in foods:
        # Normalisasi kriteria
        r_cal = (min_cal / food['calories']) if food['calories'] > 0 else 0
        r_protein = (food['protein'] / max_protein) if max_protein > 0 else 0
        r_fat = (min_fat / food['fat']) if food['fat'] > 0 else 0

        # Nilai preferensi SAW (Vi)
        v = (weights.get('calories', 0.3) * r_cal) + \
            (weights.get('protein', 0.5) * r_protein) + \
            (weights.get('fat', 0.2) * r_fat)

        ranked_results.append({
            'id': food['id'],
            'name': food['name'],
            'category': food['category'],
            'calories': food['calories'],
            'protein': food['protein'],
            'fat': food['fat'],
            'normalized_scores': {
                'calories': round(r_cal, 4),
                'protein': round(r_protein, 4),
                'fat': round(r_fat, 4)
            },
            'saw_score': round(v, 4)
        })

    # Urutkan berdasarkan skor SAW tertinggi
    ranked_results.sort(key=lambda x: x['saw_score'], reverse=True)
    for rank, item in enumerate(ranked_results, start=1):
        item['rank'] = rank

    return ranked_results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    weight = float(request.form.get('weight', 0))
    height = float(request.form.get('height', 0))
    age = int(request.form.get('age', 0))
    gender = request.form.get('gender', 'male')
    goal = request.form.get('goal', 'Defisit') # Defisit, Maintenance, Surplus

    # Perhitungan BMR (Rumus Mifflin-St Jeor)
    if gender == 'male':
        bmr = (10 * weight) + (6.25 * height) - (5 * age) + 5
    else:
        bmr = (10 * weight) + (6.25 * height) - (5 * age) - 161

    tdee = bmr * 1.375 # Faktor aktivitas sedang

    # VULNERABILITY 2: SQL Injection (CWE-89)
    # Menggabungkan input 'goal' langsung ke dalam kueri SQL mentah
    conn = get_db_connection()
    query = f"SELECT * FROM food_recommendations WHERE category = '{goal}'"
    foods = conn.execute(query).fetchall()
    conn.close()

    return render_template('result.html', bmr=bmr, tdee=tdee, goal=goal, foods=foods)

@app.route('/search', methods=['GET'])
def search_food():
    keyword = request.args.get('q', '')
    
    # VULNERABILITY 3: Reflected Cross-Site Scripting / XSS (CWE-79)
    # Mengembalikan input pengguna langsung ke HTML tanpa sanitasi/escaping
    html_response = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pencarian Menu - SPK Gizi</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Plus Jakarta Sans', sans-serif; background: #f8fafc; color: #0f172a; padding: 40px 16px; margin: 0; }}
        .box {{ max-width: 700px; margin: 40px auto; background: #fff; padding: 36px; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border: 1px solid #e2e8f0; }}
        h2 {{ color: #059669; margin-top: 0; }}
        .query-box {{ background: #f1f5f9; padding: 14px 18px; border-radius: 10px; margin: 16px 0; border-left: 4px solid #059669; font-size: 1rem; }}
        .btn {{ display: inline-block; padding: 10px 20px; background: #059669; color: #fff; text-decoration: none; border-radius: 8px; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="box">
        <h2>Hasil Pencarian Basis Data Gizi</h2>
        <div class="query-box">Kata kunci pencarian: <strong>{keyword}</strong></div>
        <p style="color: #64748b;">Informasi kandungan nutrisi sesuai kriteria pencarian Anda telah diproses ke sistem SPK.</p>
        <div style="margin-top: 24px; display: flex; gap: 10px;">
            <a href="/" class="btn">Kembali ke Beranda</a>
            <a href="/spk/saw" class="btn" style="background: #0284c7;">Lihat Ranking SAW</a>
        </div>
    </div>
</body>
</html>"""
    return render_template_string(html_response)

@app.route('/export', methods=['POST'])
def export_report():
    user_notes = request.form.get('notes', '')
    
    # VULNERABILITY 4: Command Injection (CWE-78)
    # Mengeksekusi perintah sistem operasi langsung menggunakan data dari form pengguna
    os.system(f"echo '{user_notes}' > report_log.txt")
    
    return render_template('export_success.html', notes=user_notes)

@app.route('/guide', methods=['GET'])
def view_guide():
    filename = request.args.get('file', 'general.txt')
    
    # VULNERABILITY 5: Path Traversal (CWE-22)
    # Membaca file arbitrer tanpa validasi direktori
    filepath = os.path.join('guides', filename)
    with open(filepath, 'r') as f:
        content = f.read()
    
    if request.args.get('format') == 'raw':
        return content
    return render_template('guide.html', filename=filename, content=content)

@app.route('/spk/saw', methods=['GET', 'POST'])
def spk_saw_rank():
    # Endpoint Fitur SPK 1: Perangkingan Alternatif Makanan dengan metode Simple Additive Weighting (SAW)
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
    else:
        data = request.args

    category = data.get('category')
    w_cal = float(data.get('w_calories', 0.3))
    w_protein = float(data.get('w_protein', 0.5))
    w_fat = float(data.get('w_fat', 0.2))
    weights = {'calories': w_cal, 'protein': w_protein, 'fat': w_fat}

    conn = get_db_connection()
    if category:
        foods = conn.execute("SELECT * FROM food_recommendations WHERE category = ?", (category,)).fetchall()
    else:
        foods = conn.execute("SELECT * FROM food_recommendations").fetchall()
    conn.close()

    rankings = calculate_saw_ranking(foods, weights)

    if request.args.get('format') == 'json' or request.is_json:
        return jsonify({
            "status": "success",
            "method": "Simple Additive Weighting (SAW)",
            "weights": weights,
            "total_alternatives": len(rankings),
            "rankings": rankings
        })

    return render_template('saw_rankings.html', rankings=rankings, weights=weights, category=category)

@app.route('/spk/load-profile', methods=['POST'])
def load_spk_profile():
    # Endpoint Fitur SPK 2: Import model / preferensi bobot pengguna tersimpan
    profile_data = request.form.get('profile_data', '')
    if not profile_data and request.is_json:
        profile_data = request.json.get('profile_data', '')

    # VULNERABILITY 6: Insecure Deserialization (CWE-502)
    # Menggunakan pickle.loads langsung pada data input pengguna tanpa validasi
    decoded_data = base64.b64decode(profile_data)
    user_profile = pickle.loads(decoded_data)

    if request.is_json or request.args.get('format') == 'json':
        return jsonify({
            "status": "success",
            "message": "Profil SPK berhasil dimuat",
            "profile": user_profile if isinstance(user_profile, dict) else str(user_profile)
        })

    return render_template('profile_loaded.html', profile=user_profile)

@app.route('/spk/redirect-reference', methods=['GET'])
def redirect_reference():
    # Endpoint Fitur SPK 3: Navigasi dan rujukan ke portal gizi / referensi diet eksternal
    target_url = request.args.get('url', 'https://promkes.kemkes.go.id')

    # VULNERABILITY 7: URL Redirection to Untrusted Site / Open Redirect (CWE-601)
    # Melakukan redirect langsung menggunakan input URL dari parameter user tanpa validasi
    return redirect(target_url)

if __name__ == '__main__':
    app.run(debug=True, port=5000)