import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2

logging.basicConfig(level=logging.DEBUG)

def find_all_occurrences(text, pattern):
    pos = 0
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        yield pos
        pos += 1

def find_parameter(context, param):
    try:
        st.write(f"Recherche du paramètre {param}")
        param_forms = [f'/{param} ', f'/{param}(', f'/{param}/', f'/{param}<<']
        for form in param_forms:
            start = context.find(form)
            if start != -1:
                st.write(f"Trouvé {form} à la position {start}")
                pos = start + len(form)
                if form.endswith('('):
                    end = context.find(')', pos)
                    if end != -1:
                        value = context[pos:end]
                        st.write(f"Valeur trouvée (parenthèses): '{value}'")
                        return value
                else:
                    value = ''
                    for char in context[pos:pos+10]:
                        if char in '0123456789.':
                            value += char
                        else:
                            break
                    if value:
                        return value
        return None
    except Exception as e:
        st.error(f"Erreur lors de la recherche du paramètre {param}: {str(e)}")
        return None

def extract_text_from_pdf(buffer):
    try:
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(buffer))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text
    except Exception as e:
        st.error(f"Erreur lors de l'extraction du texte: {str(e)}")
        return None

def modify_filter_params(buffer, filter_pos):
    processed_buffer = bytearray(buffer)
    content = buffer[filter_pos:filter_pos+200].decode('latin-1', errors='ignore')
    v_pos = content.find('/V ')
    if v_pos != -1:
        abs_pos = filter_pos + v_pos + 3
        processed_buffer[abs_pos:abs_pos+1] = b'0'
    return processed_buffer

def apply_key_to_svid(buffer, filter_pos):
    processed_buffer = bytearray(buffer)
    content = buffer[filter_pos:filter_pos+200].decode('latin-1', errors='ignore')
    svid_pos = content.find('SVID(')
    if svid_pos != -1:
        value_start = content.find('(', svid_pos)
        value_end = content.find(')', svid_pos)
        if value_start != -1 and value_end != -1:
            abs_value_start = filter_pos + value_start + 1
            abs_value_end = filter_pos + value_end
            key = b'NORBJ'
            field_length = abs_value_end - abs_value_start
            replacement = key + b' ' * (field_length - len(key))
            for i, byte in enumerate(replacement):
                processed_buffer[abs_value_start + i] = byte
    return processed_buffer

def process_drm(buffer, positions):
    """Déprotection du DRM FileOpen."""
    processed_buffer = bytearray(buffer)
    
    for pos in positions:
        context = buffer[pos:pos+200].decode('latin-1', errors='ignore')
        st.write(f"\nOccurrence trouvée à la position {pos}:")
        st.write("Contexte:", context)
        
        # 1. Modification SVID
        svid_pos = context.find('SVID(')
        if svid_pos != -1:
            abs_svid_start = pos + context.find('(', svid_pos) + 1
            abs_svid_end = pos + context.find(')', svid_pos)
            st.write(f"Position SVID: {abs_svid_start}-{abs_svid_end}")
            st.write("Valeur actuelle:", context[svid_pos+5:context.find(')', svid_pos)])
            replacement = b'NORBJ' + b' ' * (abs_svid_end - abs_svid_start - 5)
            st.write("Remplacement par:", replacement)
            for i, byte in enumerate(replacement):
                processed_buffer[abs_svid_start + i] = byte
        
        # 2. Modification paramètre V
        v_pos = context.find('/V ')
        if v_pos != -1:
            abs_v_pos = pos + v_pos + 3
            st.write(f"Position V: {abs_v_pos}")
            st.write("Valeur actuelle:", context[v_pos+3:v_pos+4])
            processed_buffer[abs_v_pos:abs_v_pos+1] = b'0'
            st.write("Nouvelle valeur: 0")
    
    return bytes(processed_buffer)

def analyze_pdf(file_bytes):
    """Analyse et déprotège le PDF."""
    st.write("Taille du fichier:", len(file_bytes), "bytes")
    st.write("Premiers octets:", file_bytes[:10].hex())
    try:
        if file_bytes[:4] != b'%PDF':
            raise ValueError("Format de fichier non valide - Ce n'est pas un PDF")
        
        content_latin = file_bytes.decode('latin-1', errors='ignore')
        matches = list(find_all_occurrences(content_latin, '/FOPN_foweb'))
        
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
            # Déprotection du PDF
            processed_buffer = process_drm(file_bytes, matches)
            # Extraction après déprotection
            extracted_text = extract_text_from_pdf(processed_buffer)
        else:
            processed_buffer = file_bytes
            extracted_text = extract_text_from_pdf(file_bytes)

        return drm_info, processed_buffer, extracted_text

    except Exception as e:
        st.error(f"Erreur lors de l'analyse du PDF: {str(e)}")
        raise

def main():
    st.set_page_config(page_title="Analyse DRM FileOpen", layout="wide")
    st.title("Analyse DRM FileOpen")
    
    uploaded_file = st.file_uploader("Déposez votre PDF ici", type=['pdf'])
    
    if uploaded_file:
        try:
            file_bytes = uploaded_file.getvalue()
            drm_info, processed_buffer, extracted_text = analyze_pdf(file_bytes)
            
            st.header("Résultats de l'analyse")
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Type de protection", drm_info['type'])
                st.metric("Filtre", drm_info['filter'])
            with col2:
                st.metric("Taille de la clé", drm_info['key_length'])
                st.metric("Taille du fichier", f"{drm_info['size_kb']} KB")
            
            if drm_info['has_fileopen']:
                st.warning("Ce fichier utilise une protection FileOpen avec une clé statique de 5 octets.")
                
                # Affichage du texte extrait
                if extracted_text:
                    st.write("### Contenu textuel extrait:")
                    st.text_area("Texte extrait", extracted_text, height=200)
                    
                    # Boutons de téléchargement
                    col1, col2 = st.columns(2)
                    with col1:
                        st.download_button(
                            "Télécharger le texte",
                            extracted_text,
                            file_name=f"{uploaded_file.name.replace('.pdf', '')}_text.txt",
                            mime="text/plain"
                        )
                    with col2:
                        st.download_button(
                            "Télécharger PDF traité",
                            processed_buffer,
                            file_name=f"{uploaded_file.name.replace('.pdf', '')}_unprotected.pdf",
                            mime="application/pdf"
                        )
        
        except Exception as e:
            st.error(f"Erreur : {str(e)}")

if __name__ == "__main__":
    main()
