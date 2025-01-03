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
    # On cherche dans tout le fichier, pas seulement l'en-tête
    content = pdf_bytes.hex()
    signatures = {
        'foweb': 'FOPN_foweb',
        'drm': 'FileOpen',
        'code': 'NORBJ'
    }
    
    results = {}
    for key, signature in signatures.items():
        # Recherche en binaire et en texte
        hex_sig = signature.encode('ascii').hex()
        results[key] = {
            'found': hex_sig in content or signature in pdf_bytes.decode('latin-1', errors='ignore'),
            'signature': signature
        }
    
    return results

def process_buffer(buffer, signatures):
    """Traite le buffer PDF pour retirer la protection FileOpen."""
    processed_buffer = bytearray(buffer)
    
    if signatures['foweb']['found']:
        try:
            # On cherche la position exacte du code NORBJ
            content = buffer.decode('latin-1', errors='ignore')
            code_pos = content.find('Code=')
            
            if code_pos != -1:
                st.write(f"Position 'Code=' trouvée: {code_pos}")
                # Affichage du contexte
                context_start = max(0, code_pos - 20)
                context_end = min(len(content), code_pos + 30)
                st.write("Contexte:", content[context_start:context_end])
                
                # Application de la clé NORBJ après 'Code='
                key = b'NORBJ'
                key_pos = code_pos + 5  # Position après 'Code='
                for i, byte in enumerate(key):
                    processed_buffer[key_pos + i] = byte
                    
                st.write(f"Clé NORBJ appliquée à la position {key_pos}")
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
