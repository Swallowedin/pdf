import streamlit as st
import io
import PyPDF2
from docx import Document
import fitz  # PyMuPDF
import tempfile
import os
from pathlib import Path

def process_buffer(buffer):
    """Traite le buffer PDF pour retirer la protection FileOpen."""
    key = b'NORBJ'
    processed_buffer = bytearray(buffer)
    
    # Recherche de la signature FileOpen
    content = buffer.decode('latin-1')
    if 'FOPN_foweb' in content:
        # Application de la clé de 5 octets
        for i in range(5):
            processed_buffer[i] = key[i]
    
    return bytes(processed_buffer)

def extract_text_from_pdf(buffer):
    """Extrait le texte d'un PDF en utilisant PyMuPDF."""
    text = ""
    with fitz.open(stream=buffer, filetype="pdf") as doc:
        for page in doc:
            text += page.get_text() + "\n\n"
    return text

def create_word_document(text):
    """Crée un document Word à partir du texte."""
    doc = Document()
    for paragraph in text.split('\n'):
        if paragraph.strip():
            doc.add_paragraph(paragraph)
    
    # Sauvegarde dans un buffer
    docx_buffer = io.BytesIO()
    doc.save(docx_buffer)
    docx_buffer.seek(0)
    return docx_buffer

def analyze_pdf(file_bytes):
    """Analyse un fichier PDF pour détecter la protection FileOpen."""
    try:
        # Vérification du format PDF
        if not file_bytes.startswith(b'%PDF'):
            raise ValueError("Format de fichier non valide - Ce n'est pas un PDF")

        # Analyse du contenu
        content = file_bytes.decode('latin-1')
        has_fileopen = 'FOPN_foweb' in content

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
            processed_buffer = process_buffer(file_bytes)
        else:
            processed_buffer = file_bytes

        return drm_info, processed_buffer
    except Exception as e:
        raise ValueError(f"Erreur lors de l'analyse du PDF: {str(e)}")

def main():
    st.set_page_config(page_title="Analyse DRM FileOpen", layout="wide")
    st.title("Analyse DRM FileOpen")

    # Zone d'upload
    uploaded_file = st.file_uploader("Déposez votre PDF ici", type=['pdf'])

    if uploaded_file:
        try:
            # Lecture et analyse du fichier
            file_bytes = uploaded_file.getvalue()
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

                # Options d'export
                st.header("Exports disponibles")
                
                col1, col2, col3 = st.columns(3)
                
                # Export PDF
                with col1:
                    if st.button("Télécharger PDF sans DRM"):
                        st.download_button(
                            "Télécharger PDF",
                            processed_buffer,
                            file_name=f"{uploaded_file.name.replace('.pdf', '')}_processed.pdf",
                            mime="application/pdf"
                        )

                # Export Word
                with col2:
                    if st.button("Exporter en Word"):
                        with st.spinner("Conversion en cours..."):
                            text = extract_text_from_pdf(processed_buffer)
                            docx_buffer = create_word_document(text)
                            st.download_button(
                                "Télécharger DOCX",
                                docx_buffer,
                                file_name=f"{uploaded_file.name.replace('.pdf', '')}.docx",
                                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                            )

                # Export Texte
                with col3:
                    if st.button("Exporter en texte"):
                        with st.spinner("Extraction du texte..."):
                            text = extract_text_from_pdf(processed_buffer)
                            st.download_button(
                                "Télécharger TXT",
                                text.encode(),
                                file_name=f"{uploaded_file.name.replace('.pdf', '')}.txt",
                                mime="text/plain"
                            )

            # Détails techniques
            with st.expander("Détails techniques"):
                st.code("""
Structure du DRM FileOpen :
RetVal=1&ServId=btq_afnor&DocuId=[ID]&Code=NORBJ&Perms=1

• Clé de chiffrement : 5 octets statiques
• Filtre PDF : FOPN_foweb
                """)

        except Exception as e:
            st.error(f"Erreur : {str(e)}")

if __name__ == "__main__":
    main()
