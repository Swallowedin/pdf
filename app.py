import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2

logging.basicConfig(level=logging.DEBUG)

def extract_text_from_pdf(buffer, processed_buffer=None):
    """Extrait le texte d'un PDF, en essayant d'abord le buffer original puis le buffer traité."""
    def try_extract(buf):
        try:
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(buf))
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text() + "\n"
            return text
        except Exception as e:
            st.error(f"Erreur lors de l'extraction du texte: {str(e)}")
            return None
            
    # Essai avec le buffer original
    text = try_extract(buffer)
    
    # Si échec et buffer traité disponible, essai avec celui-ci
    if text is None and processed_buffer is not None:
        text = try_extract(processed_buffer)
        if text is not None:
            st.success("Extraction réussie après traitement DRM")
            
    return text

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
        param_forms = [
            f'/{param} ',
            f'/{param}(',
            f'/{param}/',
            f'/{param}<<'
        ]
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
                        st.write(f"Valeur trouvée (numérique): '{value}'")
                        return value
        st.write(f"Paramètre {param} non trouvé")
        return None
    except Exception as e:
        st.error(f"Erreur lors de la recherche du paramètre {param}: {str(e)}")
        return None

def modify_filter_params(buffer, filter_pos):
    processed_buffer = bytearray(buffer)
    content = buffer[filter_pos:filter_pos+200].decode('latin-1', errors='ignore')
    v_pos = content.find('/V ')
    if v_pos != -1:
        abs_pos = filter_pos + v_pos + 3
        processed_buffer[abs_pos:abs_pos+1] = b'0'
        st.write(f"Modification du paramètre V à la position {abs_pos}")
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
            st.write(f"Position début valeur SVID: {abs_value_start}")
            st.write(f"Position fin valeur SVID: {abs_value_end}")
            st.write("Valeur actuelle:", content[value_start+1:value_end])
            key = b'NORBJ'
            field_length = abs_value_end - abs_value_start
            replacement = key + b' ' * (field_length - len(key))
            st.write("Contenu avant modification:", 
                processed_buffer[abs_value_start:abs_value_end].hex())
            for i, byte in enumerate(replacement):
                processed_buffer[abs_value_start + i] = byte
            st.write("Contenu après modification:", 
                processed_buffer[abs_value_start:abs_value_end].hex())
    return processed_buffer

def process_drm(buffer, positions):
    processed_buffer = bytearray(buffer)
    for pos in positions:
        processed_buffer = apply_key_to_svid(processed_buffer, pos)
        processed_buffer = modify_filter_params(processed_buffer, pos)
    return bytes(processed_buffer)

def analyze_pdf(file_bytes):
    try:
        if file_bytes[:4] != b'%PDF':
            raise ValueError("Format de fichier non valide - Ce n'est pas un PDF")
        
        st.write("En-tête PDF valide détectée")
        
        # Traitement DRM si nécessaire
        has_fileopen = len(matches) > 0
        if has_fileopen:
            processed_buffer = process_drm(file_bytes, matches)
        else:
            processed_buffer = file_bytes
            
        # Extraction du texte
        extracted_text = extract_text_from_pdf(file_bytes, processed_buffer)
        if extracted_text:
            st.write("### Contenu textuel extrait du PDF:")
            st.text_area("Texte extrait", extracted_text, height=200)
        
        content_latin = file_bytes.decode('latin-1', errors='ignore')
        matches = list(find_all_occurrences(content_latin, '/FOPN_foweb'))
        st.write(f"Nombre d'occurrences de FOPN_foweb trouvées: {len(matches)}")
        
        for i, pos in enumerate(matches):
            context_start = max(0, pos - 100)
            context_end = min(len(content_latin), pos + 200)
            context = content_latin[context_start:context_end]
            st.write(f"\nOccurrence {i+1} à la position {pos}:")
            st.write("Contexte étendu:", context)
            
            params = {
                'V': find_parameter(context, 'V'),
                'Length': find_parameter(context, 'Length'),
                'VEID': find_parameter(context, 'VEID'),
                'BUILD': find_parameter(context, 'BUILD'),
                'SVID': find_parameter(context, 'SVID'),
                'DUID': find_parameter(context, 'DUID')
            }
            st.write("Paramètres trouvés:", params)
        
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
            processed_buffer = process_drm(file_bytes, matches)
        else:
            processed_buffer = file_bytes
        
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
            st.write("Type du fichier uploadé:", type(uploaded_file))
            st.write("Attributs du fichier:", dir(uploaded_file))
            
            file_bytes = uploaded_file.getvalue()
            st.write("Taille du fichier:", len(file_bytes), "bytes")
            st.write("Premiers octets:", file_bytes[:10].hex())
            
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
                st.warning(
                    "Ce fichier utilise une protection FileOpen avec une clé statique de 5 octets. "
                    "Dans un contexte de production, il est recommandé d'utiliser des méthodes de protection plus robustes."
                )
                
                if extracted_text:
                    with open("extracted_text.txt", "w", encoding="utf-8") as f:
                        f.write(extracted_text)
                    st.download_button(
                        "Télécharger le texte extrait",
                        extracted_text,
                        file_name=f"{uploaded_file.name.replace('.pdf', '')}_text.txt",
                        mime="text/plain"
                    )
                
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
