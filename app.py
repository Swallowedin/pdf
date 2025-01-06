import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2
from openai import OpenAI
import json
import hashlib
from datetime import datetime
import traceback
import re

# Configuration du logging
logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@st.cache_resource
def get_openai_client():
    try:
        client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])
        return client
    except Exception as e:
        logger.error(f"Erreur d'initialisation OpenAI: {str(e)}")
        return None

@st.cache_data(ttl=3600)
def analyze_drm_with_openai(context_hex, context_ascii, obj_number, fopn_pos=None):
    try:
        client = get_openai_client()
        if not client:
            return None

        prompt = f"""Analyse ce contexte PDF spécifique qui contient une protection DRM FileOpen. Trouve les positions EXACTES dans le contexte fourni.

Contexte actuel:
Objet PDF: {obj_number}
Position FOPN: {fopn_pos}
HEX: {context_hex[:300]}
ASCII: {context_ascii[:300]}

IMPORTANT: Analyse le contexte fourni pour trouver les positions RÉELLES :
1. Cherche '/FOPN_foweb' dans le contexte et donne sa position relative
2. Trouve '/V 1' en partant de la position FOPN et donne son offset
3. Localise '/INFO(' et 'endstream' pour les limites du stream

Retourne un JSON avec cette structure:
{{
    "modifications": [
        {{
            "type": "filter",
            "position": <position_relative_de_FOPN>,
            "longueur": <longueur_reelle>,
            "valeur": "/Filter/FlateDecode"
        }},
        {{
            "type": "version",
            "position": <position_relative_de_V1>,
            "longueur": 1,
            "valeur": "0"
        }}
    ],
    "stream": {{
        "debut": <position_relative_INFO>,
        "fin": <position_relative_endstream>,
        "effacement_necessaire": true
    }},
    "warnings": [
        "messages d'avertissement"
    ]
}}

IMPORTANT: Les positions doivent être calculées en analysant le HEX et ASCII fournis."""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "Tu es un expert en analyse hexadécimale et PDF. Analyse le contexte RÉEL fourni pour trouver les positions EXACTES."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            response_format={ "type": "json_object" },
            temperature=0
        )
        
        try:
            analysis = json.loads(response.choices[0].message.content)
            logger.debug(f"Positions trouvées: {json.dumps(analysis, indent=2)}")
            return analysis
        except json.JSONDecodeError as e:
            logger.error(f"Réponse OpenAI non valide: {e}")
            logger.error(f"Contenu reçu: {response.choices[0].message.content}")
            return None
            
    except Exception as e:
        logger.error(f"Erreur analyse OpenAI: {str(e)}")
        return None

def process_drm_with_ai(buffer, positions):
    processed = bytearray(buffer)
    modifications_log = []
    
    for fopn_pos in positions:
        try:
            # Extrait le contexte
            start_pos = max(0, fopn_pos - 200)
            end_pos = min(len(buffer), fopn_pos + 2000)
            context = buffer[start_pos:end_pos]
            
            # Prépare les données
            hex_dump = ' '.join([f"{b:02x}" for b in context])
            ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in context])
            obj_number = extract_object_number(ascii_dump)
            
            # Obtient l'analyse d'OpenAI avec la position FOPN
            analysis = analyze_drm_with_openai(hex_dump, ascii_dump, obj_number, fopn_pos)
            
            if analysis:
                st.write("📊 Analyse DRM OpenAI:")
                st.json(analysis)
                
                try:
                    # Applique les modifications
                    for mod in analysis.get('modifications', []):
                        abs_pos = fopn_pos + mod.get('position', 0)
                        length = mod.get('longueur', 0)
                        new_value = mod.get('valeur', '').encode('ascii')
                        
                        if 0 <= abs_pos < len(processed) and length > 0:
                            modifications_log.append({
                                'position': abs_pos,
                                'type': mod.get('type'),
                                'original': processed[abs_pos:abs_pos+length].hex(),
                                'new': new_value.hex()
                            })
                            processed[abs_pos:abs_pos+length] = new_value.ljust(length, b'\x00')
                            logger.info(f"Modification appliquée: {mod['type']} à {abs_pos}")

                    # Traite le stream
                    stream = analysis.get('stream', {})
                    if stream and stream.get('effacement_necessaire'):
                        abs_start = fopn_pos + stream.get('debut', 0)
                        abs_end = fopn_pos + stream.get('fin', 0)
                        
                        if 0 <= abs_start < abs_end < len(processed):
                            processed[abs_start:abs_end] = b'\x00' * (abs_end - abs_start)
                            logger.info(f"Stream effacé: {abs_start}-{abs_end}")

                    # Affiche les avertissements
                    for warning in analysis.get('warnings', []):
                        st.warning(f"⚠️ {warning}")
                except Exception as e:
                    logger.error(f"Erreur application modifications: {str(e)}")
                    st.error(f"Erreur modifications: {str(e)}")
            
            else:
                # Mode standard si OpenAI échoue
                st.warning("Mode standard activé (OpenAI indisponible)")
                logger.warning("Utilisation du mode standard")
                try:
                    processed[fopn_pos:fopn_pos+18] = b'/Filter/FlateDecode'
                    
                    v_pos = buffer[fopn_pos:end_pos].find(b'/V 1')
                    if v_pos != -1:
                        v_abs = fopn_pos + v_pos + 3
                        processed[v_abs] = ord('0')
                        
                    info_pos = buffer[fopn_pos:end_pos].find(b'/INFO(')
                    if info_pos != -1:
                        stream_start = fopn_pos + info_pos
                        stream_end = buffer[stream_start:end_pos].find(b'endstream')
                        if stream_end != -1:
                            abs_stream_end = stream_start + stream_end
                            processed[stream_start:abs_stream_end] = b'\x00' * (abs_stream_end - stream_start)
                except Exception as e:
                    logger.error(f"Erreur mode standard: {str(e)}")
                    st.error(f"Erreur mode standard: {str(e)}")
        
        except Exception as e:
            logger.error(f"Erreur position {fopn_pos}: {str(e)}")
            logger.error(traceback.format_exc())
            st.error(f"⚠️ Erreur position {fopn_pos}: {str(e)}")
            continue
    
    return bytes(processed)

def extract_object_number(context):
    """Extrait le numéro d'objet PDF du contexte"""
    try:
        obj_match = re.search(r'(\d+)\s+0\s+obj', context)
        if obj_match:
            return obj_match.group(1)
        return None
    except Exception:
        return None

def find_all_occurrences(text, pattern):
    """Trouve toutes les occurrences d'un pattern dans le texte"""
    pos = 0
    occurrences = []
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        occurrences.append(pos)
        pos += 1
    logger.info(f"Trouvé {len(occurrences)} occurrences de {pattern}")
    return occurrences

def extract_text_from_pdf(buffer):
    """Extrait le texte du PDF"""
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(buffer), strict=False)
        text = []
        for i, page in enumerate(pdf_reader.pages):
            try:
                text.append(f"=== Page {i+1} ===\n{page.extract_text()}")
                logger.info(f"Page {i+1} extraite avec succès")
            except Exception as e:
                logger.error(f"Erreur extraction page {i+1}: {str(e)}")
                text.append(f"=== Page {i+1} ===\n[Erreur extraction]")
        return '\n\n'.join(text)
    except Exception as e:
        logger.error(f"Erreur extraction globale: {str(e)}")
        return None

def analyze_pdf(file_bytes):
    """Analyse principale du PDF avec support OpenAI"""
    logger.info("=== DÉBUT ANALYSE PDF ===")
    st.write("=== DÉBUT ANALYSE PDF ===")
    
    if not file_bytes[:4] == b'%PDF':
        raise ValueError("Format PDF invalide")
    
    # Informations de base
    file_info = {
        'size': len(file_bytes),
        'version': file_bytes[5:8].decode('ascii', errors='ignore'),
        'has_fileopen': False
    }
    
    content = file_bytes.decode('latin-1', errors='ignore')
    matches = list(find_all_occurrences(content, '/FOPN_foweb'))
    
    if not matches:
        logger.info("Aucune protection détectée")
        return file_info, file_bytes, extract_text_from_pdf(file_bytes)
    
    file_info.update({
        'has_fileopen': True,
        'type': 'FileOpen DRM',
        'filter': 'FOPN_foweb',
        'key_length': '5 bytes',
        'size_kb': round(len(file_bytes) / 1024),
        'protection_count': len(matches)
    })
    
    processed = process_drm_with_ai(file_bytes, matches)
    text = extract_text_from_pdf(processed)
    
    return file_info, processed, text

def collect_training_data(files_data):
    """Collecte les données pour le fine-tuning à partir de plusieurs fichiers"""
    training_examples = []
    for filename, (hex_dump, ascii_dump, fopn_pos, result) in files_data.items():
        example = {
            "context_hex": hex_dump,
            "context_ascii": ascii_dump,
            "fopn_position": fopn_pos,
            "analysis_result": result
        }
        training_examples.append(example)
    return training_examples

def compare_drm_structures(files_data):
    """Compare les structures DRM entre les fichiers"""
    comparisons = {
        "positions_relatives": {},
        "tailles_stream": {},
        "patterns_communs": set()
    }
    
    for filename, (hex_dump, ascii_dump, fopn_pos, result) in files_data.items():
        if result:
            # Analyser les positions relatives des éléments
            for mod in result.get('modifications', []):
                element = mod.get('type')
                pos = mod.get('position')
                if element:
                    if element not in comparisons["positions_relatives"]:
                        comparisons["positions_relatives"][element] = []
                    comparisons["positions_relatives"][element].append(pos)
            
            # Analyser les tailles de stream
            stream = result.get('stream', {})
            if stream:
                taille = stream.get('fin', 0) - stream.get('debut', 0)
                comparisons["tailles_stream"][filename] = taille
    
    return comparisons

def show_batch_analysis(files):
    """Interface pour l'analyse par lot"""
    results_container = st.empty()
    
    if st.button("🔄 Analyser tous les fichiers"):
        progress_bar = st.progress(0)
        results = []
        files_data = {}
        
        with st.spinner("Analyse comparative en cours..."):
            for idx, file in enumerate(files):
                bytes_data = file.getvalue()
                fopn_pos = find_first_fopn(bytes_data)
                if fopn_pos:
                    # Extraire le contexte
                    start_pos = max(0, fopn_pos - 200)
                    end_pos = min(len(bytes_data), fopn_pos + 2000)
                    context = bytes_data[start_pos:end_pos]
                    
                    hex_dump = ' '.join([f"{b:02x}" for b in context])
                    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in context])
                    
                    # Analyser avec OpenAI en précisant que les positions doivent être relatives
                    analysis = analyze_drm_with_openai(hex_dump, ascii_dump, extract_object_number(ascii_dump), fopn_pos)
                    files_data[file.name] = (hex_dump, ascii_dump, fopn_pos, analysis)
                
                progress_bar.progress((idx + 1) / len(files))
                results.append((file.name, fopn_pos, analysis))

        # Afficher l'analyse comparative
        with results_container:
            st.write("### 📊 Analyse comparative des DRM")
            
            # Tableau comparatif
            st.write("#### 📈 Comparaison des positions")
            data = []
            for name, fopn_pos, analysis in results:
                if analysis:
                    filter_pos = next((m for m in analysis.get('modifications', []) 
                                     if m.get('type') == 'filter'), {}).get('position', 'N/A')
                    version_pos = next((m for m in analysis.get('modifications', []) 
                                      if m.get('type') == 'version'), {}).get('position', 'N/A')
                    stream_size = (analysis.get('stream', {}).get('fin', 0) - 
                                 analysis.get('stream', {}).get('debut', 0))
                    
                    data.append({
                        "Fichier": name,
                        "Position FOPN": fopn_pos,
                        "Offset filtre": filter_pos,
                        "Offset version": version_pos,
                        "Taille stream": stream_size
                    })
            
            if data:
                st.dataframe(data)
                
                # Statistiques
                st.write("#### 📊 Statistiques")
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Positions relatives moyennes:**")
                    offsets = [d["Offset filtre"] for d in data if d["Offset filtre"] != 'N/A']
                    if offsets:
                        st.write(f"- Filtre: {sum(offsets)/len(offsets):.2f}")
                    
                    offsets = [d["Offset version"] for d in data if d["Offset version"] != 'N/A']
                    if offsets:
                        st.write(f"- Version: {sum(offsets)/len(offsets):.2f}")
                
                with col2:
                    st.write("**Tailles des streams:**")
                    sizes = [d["Taille stream"] for d in data]
                    if sizes:
                        st.write(f"- Min: {min(sizes)}")
                        st.write(f"- Max: {max(sizes)}")
                        st.write(f"- Moyenne: {sum(sizes)/len(sizes):.2f}")
            
            # Générer les données d'entraînement
            training_data = collect_training_data(files_data)
            
            # Bouton pour télécharger les données d'entraînement
            if training_data:
                st.download_button(
                    "📥 Télécharger les données d'entraînement",
                    data=json.dumps(training_data, indent=2),
                    file_name="training_data.json",
                    mime="application/json"
                )
                
def find_first_fopn(buffer):
    """Trouve la première occurrence de FOPN_foweb"""
    content = buffer.decode('latin-1', errors='ignore')
    pos = content.find('/FOPN_foweb')
    return pos if pos != -1 else None

def main():
    st.set_page_config(page_title="DRM FileOpen", layout="wide")
    st.title("🔓 DRM FileOpen Analyzer")
    
    # Vérification de la configuration OpenAI
    client = get_openai_client()
    if not client:
        st.warning("⚠️ API OpenAI non configurée - mode standard actif")
    else:
        st.success("✅ API OpenAI connectée")
    
    # Upload des fichiers avec indications claires
    st.markdown("### 📂 Sélection des fichiers")
    files = st.file_uploader(
        "PDF à traiter", 
        type=['pdf'], 
        accept_multiple_files=True,
        help="Vous pouvez sélectionner plusieurs fichiers en maintenant CTRL (ou CMD sur Mac)"
    )
    
    if not files:
        st.info("💡 Glissez-déposez un ou plusieurs fichiers PDF ici, ou cliquez pour les sélectionner")
        return
        
    st.markdown(f"### 📊 {len(files)} fichier(s) à analyser")
    
    # Analyse comparative si plusieurs fichiers
    if len(files) > 1:
        st.write("### 🔍 Analyse comparative disponible")
        col1, col2 = st.columns(2)
        with col1:
            do_batch = st.checkbox("Activer l'analyse comparative", value=True)
        with col2:
            if do_batch:
                do_individual = st.checkbox("Garder l'analyse individuelle", value=True)
                if do_individual:
                    st.info("Les fichiers seront analysés individuellement après l'analyse comparative")
                
        if do_batch:
            show_batch_analysis(files)
            
        if not do_individual:
            return
    
    # Analyse individuelle des fichiers
    for file in files:
        try:
            st.markdown(f"""---
### 📄 Analyse de {file.name}""")
            bytes_data = file.getvalue()
            
            with st.spinner("🔍 Analyse en cours..."):
                info, processed, text = analyze_pdf(bytes_data)
            
            # Affichage des métriques dans un conteneur
            with st.container():
                st.markdown("#### 📊 Informations générales")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Protection", info.get('type', 'Aucune'))
                    st.metric("Filtre", info.get('filter', 'N/A'))
                with col2:
                    st.metric("Clé", info.get('key_length', 'N/A'))
                    st.metric("Taille", f"{info.get('size_kb', 0)} KB")
                with col3:
                    st.metric("Version PDF", info.get('version', 'N/A'))
                    if info.get('protection_count'):
                        st.metric("Protections", info['protection_count'])
            
            # Résultats et boutons de téléchargement
            if info['has_fileopen']:
                st.warning("🔓 Protection FileOpen détectée et déprotégée")
                
                col1, col2 = st.columns(2)
                with col1:
                    with st.expander("📝 Texte extrait", expanded=False):
                        if text:
                            st.text_area("Contenu", text, height=200)
                        else:
                            st.error("❌ Extraction du texte impossible")
                            
                with col2:
                    with st.expander("💾 Téléchargements", expanded=True):
                        st.markdown("#### 📥 Fichiers disponibles")
                        dl_col1, dl_col2, dl_col3 = st.columns(3)
                        with dl_col1:
                            if text:
                                st.download_button(
                                    "📄 Texte extrait",
                                    text,
                                    file_name=f"{file.name}_text.txt",
                                    mime="text/plain",
                                    help="Télécharger le texte extrait du PDF"
                                )
                        with dl_col2:
                            st.download_button(
                                "📝 Fichier brut",
                                bytes_data,
                                file_name=f"{file.name}_raw.txt",
                                mime="text/plain",
                                help="Télécharger les données brutes du PDF"
                            )
                        with dl_col3:
                            st.download_button(
                                "🔓 PDF déprotégé",
                                processed,
                                file_name=f"{file.name}_unprotected.pdf",
                                mime="application/pdf",
                                help="Télécharger le PDF sans protection DRM"
                            )
            else:
                st.success("✅ Aucune protection détectée")
                
        except Exception as e:
            logger.error(traceback.format_exc())
            st.error(f"❌ Erreur lors de l'analyse de {file.name}: {str(e)}")
            continue
        
        st.markdown("---")

if __name__ == "__main__":
    main()
