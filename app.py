import streamlit as st
import io
import logging
import tempfile
import os
from pathlib import Path

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)

def find_filter_position(content_latin, content_utf8):
    """Trouve la position exacte du filtre FOPN_foweb."""
    pos_latin = content_latin.find('/FOPN_foweb')
    pos_utf8 = content_utf8.find('/FOPN_foweb')
    
    # On prend la position valide
    if pos_latin != -1:
        return pos_latin
    return pos_utf8

def analyze_pdf(file_bytes):
    """Analyse un fichier PDF pour détecter la protection FileOpen."""
    try:
        if file_bytes[:4] != b'%PDF':
            raise ValueError("Format de fichier non valide - Ce n'est pas un PDF")
        
        st.write("En-tête PDF valide détectée")
        
        # Décodage du contenu
        content_latin = file_bytes.decode('latin-1', errors='ignore')
        
        # Recherche de tous les objets avec FOPN_foweb
        matches = list(find_all_occurrences(content_latin, '/FOPN_foweb'))
        st.write(f"Nombre d'occurrences de FOPN_foweb trouvées: {len(matches)}")
        
        # Analyse du contexte pour chaque occurrence
        for i, pos in enumerate(matches):
            context_start = max(0, pos - 100)
            context_end = min(len(content_latin), pos + 200)
            context = content_latin[context_start:context_end]
            st.write(f"\nOccurrence {i+1} à la position {pos}:")
            st.write("Contexte étendu:", context)
            
            # Recherche de paramètres spécifiques
            params = {
                'V': find_parameter(context, 'V'),
                'Length': find_parameter(context, 'Length'),
                'VEID': find_parameter(context, 'VEID'),
                'BUILD': find_parameter(context, 'BUILD'),
                'SVID': find_parameter(context, 'SVID'),
                'DUID': find_parameter(context, 'DUID')
            }
            st.write("Paramètres trouvés:", params)
            
            # Recherche d'autres mots-clés potentiellement intéressants
            for keyword in ['stream', 'endstream', 'obj', 'endobj', 'xref']:
                idx = context.find(keyword)
                if idx != -1:
                    st.write(f"Mot-clé '{keyword}' trouvé à la position relative: {idx}")
        
        # Cherche les autres filtres PDF dans le document
        filters = ['FlateDecode', 'DCTDecode', 'ASCII85Decode']
        for filter_name in filters:
            if f'/{filter_name}' in content_latin:
                st.write(f"Filtre supplémentaire trouvé: {filter_name}")
        
        has_fileopen = len(matches) > 0
        drm_info = {
            'has_fileopen': has_fileopen,
            'type': 'FileOpen DRM' if has_fileopen else 'Pas de DRM FileOpen détecté',
            'filter': 'FOPN_foweb' if has_fileopen else 'N/A',
            'key_length': '5 bytes' if has_fileopen else 'N/A',
            'file_size': len(file_bytes),
            'size_kb': round(len(file_bytes) / 1024)
        }
        
        if has_fileopen:
            processed_buffer = process_multiple_occurrences(file_bytes, matches)
        else:
            processed_buffer = file_bytes
        
        return drm_info, processed_buffer
        
    except Exception as e:
        st.error(f"Erreur lors de l'analyse du PDF: {str(e)}")
        raise

def find_all_occurrences(text, pattern):
    """Trouve toutes les occurrences d'un pattern dans le texte."""
    pos = 0
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        yield pos
        pos += 1

def find_parameter(context, param):
    """Trouve la valeur d'un paramètre dans le contexte."""
    try:
        start = context.find(f'/{param}')
        if start == -1:
            return None
            
        # Cherche la valeur
        after_param = context[start + len(param) + 1:]
        if after_param.startswith('('):
            end = after_param.find(')')
            if end != -1:
                return after_param[1:end]
        else:
            # Pour les valeurs numériques
            value = ''
            for char in after_param:
                if char.isdigit() or char == '.':
                    value += char
                else:
                    break
            return value if value else None
    except:
        return None

def process_multiple_occurrences(buffer, positions):
    """Traite toutes les occurrences de la protection."""
    processed_buffer = bytearray(buffer)
    
    for pos in positions:
        # Applique différentes stratégies de modification
        # 1. Modification du SVID
        processed_buffer = apply_key_to_svid(processed_buffer, pos)
        # 2. Modification des paramètres V et Length
        processed_buffer = modify_filter_params(processed_buffer, pos)
        
    return bytes(processed_buffer)

def apply_key_to_svid(buffer, filter_pos):
    """Applique la clé NORBJ au champ SVID."""
    processed_buffer = bytearray(buffer)
    content = buffer[filter_pos:filter_pos+200].decode('latin-1', errors='ignore')
    
    svid_pos = content.find('SVID(')
    if svid_pos != -1:
        abs_pos = filter_pos + svid_pos
        value_start = content.find('(', svid_pos) + filter_pos + 1
        value_end = content.find(')', svid_pos) + filter_pos
        
        if value_start < value_end:
            key = b'NORBJ'
            padding = b' ' * (value_end - value_start - len(key))
            replacement = key + padding
            
            st.write(f"Application de la clé NORBJ à la position {value_start}")
            for i, byte in enumerate(replacement):
                processed_buffer[value_start + i] = byte
    
    return processed_buffer

def modify_filter_params(buffer, filter_pos):
    """Modifie les paramètres du filtre."""
    processed_buffer = bytearray(buffer)
    content = buffer[filter_pos:filter_pos+200].decode('latin-1', errors='ignore')
    
    # Modification du paramètre V
    v_pos = content.find('/V ')
    if v_pos != -1:
        abs_pos = filter_pos + v_pos + 3
        processed_buffer[abs_pos:abs_pos+1] = b'0'  # Change V 1 en V 0
        
    return processed_buffer

def analyze_pdf(file_bytes):
    """Analyse un fichier PDF pour détecter la protection FileOpen."""
    try:
        if file_bytes[:4] != b'%PDF':
            raise ValueError("Format de fichier non valide - Ce n'est pas un PDF")
        
        st.write("En-tête PDF valide détectée")
        
        # Décodage du contenu
        content_latin = file_bytes.decode('latin-1', errors='ignore')
        content_utf8 = file_bytes.decode('utf-8', errors='ignore')
        
        # Recherche du filtre
        filter_pos = find_filter_position(content_latin, content_utf8)
        has_fileopen = filter_pos != -1
        
        if has_fileopen:
            st.write(f"Filtre FOPN_foweb trouvé à la position: {filter_pos}")
            # Affichage du contexte
            context_start = max(0, filter_pos - 50)
            context_end = min(len(content_latin), filter_pos + 100)
            st.write("Contexte:", content_latin[context_start:context_end])
        
        # Construction des infos DRM
        drm_info = {
            'has_fileopen': has_fileopen,
            'type': 'FileOpen DRM' if has_fileopen else 'Pas de DRM FileOpen détecté',
            'filter': 'FOPN_foweb' if has_fileopen else 'N/A',
            'key_length': '5 bytes' if has_fileopen else 'N/A',
            'file_size': len(file_bytes),
            'size_kb': round(len(file_bytes) / 1024)
        }
        
        if has_fileopen:
            processed_buffer = process_buffer(file_bytes, filter_pos)
            if processed_buffer[:4] != b'%PDF':
                st.error("Le traitement a corrompu l'en-tête PDF")
                return drm_info, file_bytes
        else:
            processed_buffer = file_bytes
        
        return drm_info, processed_buffer
        
    except Exception as e:
        st.error(f"Erreur lors de l'analyse du PDF: {str(e)}")
        raise

def main():
    st.set_page_config(page_title="Analyse DRM FileOpen", layout="wide")
    st.title("Analyse DRM FileOpen")
    
    uploaded_file = st.file_uploader("Déposez votre PDF ici", type=['pdf'])
    
    if uploaded_file:
        try:
            # Debug information
            st.write("Type du fichier uploadé:", type(uploaded_file))
            st.write("Attributs du fichier:", dir(uploaded_file))
            
            # Lecture du fichier
            file_bytes = uploaded_file.getvalue()
            st.write("Taille du fichier:", len(file_bytes), "bytes")
            st.write("Premiers octets:", file_bytes[:10].hex())
            
            # Analyse du PDF
            drm_info, processed_buffer = analyze_pdf(file_bytes)
            
            # Affichage des résultats
            st.header("Résultats de l'analyse")
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Type de protection", drm_info['type'])
                st.metric("Filtre", drm_info['filter'])
            with col2:
                st.metric("Taille de la clé", drm_info['key_length'])
                st.metric("Taille du fichier", f"{drm_info['size_kb']} KB")
            
            if drm_info['has_fileopen']:
                st.warning(
                    "Ce fichier utilise une protection FileOpen avec une clé statique de 5 octets. "
                    "Dans un contexte de production, il est recommandé d'utiliser des méthodes de protection plus robustes."
                )
                
                # Option de téléchargement
                st.download_button(
                    "Télécharger PDF traité",
                    processed_buffer,
                    file_name=f"{uploaded_file.name.replace('.pdf', '')}_processed.pdf",
                    mime="application/pdf"
                )
            
        except Exception as e:
            st.error(f"Erreur : {str(e)}")

if __name__ == "__main__":
    main()
