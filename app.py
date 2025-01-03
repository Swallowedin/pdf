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

def process_buffer(buffer, filter_position):
    """Traite le buffer PDF pour retirer la protection FileOpen."""
    if filter_position == -1:
        st.error("Position du filtre non trouvée")
        return buffer
        
    processed_buffer = bytearray(buffer)
    
    try:
        # La clé est appliquée dans le champ pdftools
        key = b'NORBJ'
        
        # On cherche SVID(pdftools)
        content = buffer[filter_position:filter_position+200].decode('latin-1', errors='ignore')
        svid_pos = content.find('SVID(')
        
        if svid_pos != -1:
            # On cherche la parenthèse ouvrante
            value_start = content.find('(', svid_pos)
            if value_start != -1:
                # Position absolue pour le début de la valeur
                abs_value_pos = filter_position + value_start + 1
                
                st.write(f"Position de la valeur SVID trouvée à: {abs_value_pos}")
                st.write("Contexte avant modification:", 
                    content[svid_pos:svid_pos+30])
                
                # On écrit la clé au début de la valeur
                st.write("Contenu avant modification:", 
                    processed_buffer[abs_value_pos:abs_value_pos+10].hex())
                
                for i, byte in enumerate(key):
                    processed_buffer[abs_value_pos + i] = byte
                    
                st.write("Contenu après modification:", 
                    processed_buffer[abs_value_pos:abs_value_pos+10].hex())
                    
                st.write("Contexte après modification:", 
                    processed_buffer[filter_position+svid_pos:filter_position+svid_pos+30].decode('latin-1', errors='ignore'))
            else:
                st.error("Valeur SVID non trouvée")
                return buffer
        else:
            st.error("Tag SVID non trouvé")
            return buffer
            
    except Exception as e:
        st.error(f"Erreur lors du traitement de la clé: {str(e)}")
        return buffer
    
    return bytes(processed_buffer)

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
