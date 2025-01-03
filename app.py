import streamlit as st
import io
import logging
import tempfile
import os
from pathlib import Path

# Configuration du logging
logging.basicConfig(level=logging.DEBUG)

def search_fileopen_signature(pdf_bytes):
    """Recherche les signatures FileOpen dans le PDF."""
    # Décodage du contenu avec différents encodages pour être sûr
    content_latin = pdf_bytes.decode('latin-1', errors='ignore')
    content_utf8 = pdf_bytes.decode('utf-8', errors='ignore')
    content_hex = pdf_bytes.hex()
    
    # Recherche exacte avec contexte
    foweb_pos_latin = content_latin.find('FOPN_foweb')
    foweb_pos_utf8 = content_utf8.find('FOPN_foweb')
    
    # Affichage du contexte si trouvé
    if foweb_pos_latin != -1:
        st.write("Signature FOPN_foweb trouvée (latin-1) à la position:", foweb_pos_latin)
        context_start = max(0, foweb_pos_latin - 50)
        context_end = min(len(content_latin), foweb_pos_latin + 50)
        st.write("Contexte (latin-1):", content_latin[context_start:context_end])
    
    if foweb_pos_utf8 != -1 and foweb_pos_utf8 != foweb_pos_latin:
        st.write("Signature FOPN_foweb trouvée (utf-8) à la position:", foweb_pos_utf8)
        context_start = max(0, foweb_pos_utf8 - 50)
        context_end = min(len(content_utf8), foweb_pos_utf8 + 50)
        st.write("Contexte (utf-8):", content_utf8[context_start:context_end])
    
    # Recherche de patterns spécifiques
    patterns = {
        'filter': '/FOPN_foweb',
        'code': 'Code=NORBJ',
        'code_alt': 'Code=',
        'drm': 'FileOpen'
    }
    
    st.write("\nRecherche de patterns spécifiques:")
    results = {}
    for key, pattern in patterns.items():
        pos_latin = content_latin.find(pattern)
        pos_utf8 = content_utf8.find(pattern)
        st.write(f"Pattern '{pattern}':")
        st.write(f"- Position (latin-1): {pos_latin}")
        st.write(f"- Position (utf-8): {pos_utf8}")
        if pos_latin != -1:
            context_start = max(0, pos_latin - 20)
            context_end = min(len(content_latin), pos_latin + 20)
            st.write(f"- Contexte (latin-1): {content_latin[context_start:context_end]}")
    
    # Retourne les résultats pour la compatibilité
    return {
        'foweb': {'found': foweb_pos_latin != -1 or foweb_pos_utf8 != -1, 'signature': 'FOPN_foweb'},
        'drm': {'found': 'FileOpen' in content_latin or 'FileOpen' in content_utf8, 'signature': 'FileOpen'},
        'code': {'found': 'NORBJ' in content_latin or 'NORBJ' in content_utf8, 'signature': 'NORBJ'}
    }

def process_buffer(buffer, filter_pos):
    """Traite le buffer PDF pour retirer la protection FileOpen."""
    processed_buffer = bytearray(buffer)
    
    try:
        # La clé est appliquée après le filtre
        key = b'NORBJ'
        key_pos = filter_pos + len('/FOPN_foweb')  # Position après le filtre
        
        # Affichage du contexte avant modification
        st.write(f"Zone de modification (avant):", processed_buffer[key_pos:key_pos+20].hex())
        
        # Application de la clé
        for i, byte in enumerate(key):
            processed_buffer[key_pos + i] = byte
            
        st.write(f"Zone de modification (après):", processed_buffer[key_pos:key_pos+20].hex())
        
    except Exception as e:
        st.error(f"Erreur lors du traitement de la clé: {str(e)}")
    
    return bytes(processed_buffer)

def analyze_pdf(file_bytes):
    """Analyse un fichier PDF pour détecter la protection FileOpen."""
    try:
        # Vérification de l'en-tête PDF
        if file_bytes[:4] != b'%PDF':
            raise ValueError("Format de fichier non valide - Ce n'est pas un PDF")
            
        st.write("En-tête PDF valide détectée")
        
        # Recherche des signatures FileOpen
        signatures = search_fileopen_signature(file_bytes)
        
        # Affichage des résultats de recherche
        st.write("Résultats de la recherche de signatures :")
        for key, result in signatures.items():
            st.write(f"- {result['signature']}: {'trouvé' if result['found'] else 'non trouvé'}")

        has_fileopen = signatures['foweb']['found']
        
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
            processed_buffer = process_buffer(file_bytes, signatures)
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
            
            # Affichage des premiers octets en hex pour debug
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

            # Détails techniques
            with st.expander("Détails techniques"):
                st.code("""
Structure du DRM FileOpen :
RetVal=1&ServId=btq_afnor&DocuId=[ID]&Code=NORBJ&Perms=1

• Clé de chiffrement : 5 octets statiques (NORBJ)
• Filtre PDF : FOPN_foweb
                """)

        except Exception as e:
            st.error(f"Erreur : {str(e)}")

if __name__ == "__main__":
    main()
