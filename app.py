import streamlit as st
import io
import logging
from pathlib import Path
import PyPDF2

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def dump_buffer(buffer, start, length, prefix=""):
    """Affiche le contenu d'un buffer en hex et ascii."""
    hex_dump = ' '.join([f"{b:02x}" for b in buffer[start:start+length]])
    ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in buffer[start:start+length]])
    st.write(f"{prefix} HEX: {hex_dump}")
    st.write(f"{prefix} ASCII: {ascii_dump}")

def find_all_occurrences(text, pattern):
    pos = 0
    while True:
        pos = text.find(pattern, pos)
        if pos == -1:
            break
        yield pos
        pos += 1

def find_parameter(context, param, abs_pos):
    """Trouve un paramètre avec logging détaillé."""
    st.write(f"\n=== Recherche paramètre {param} depuis position {abs_pos} ===")
    try:
        param_forms = [
            {'pattern': f'/{param} ', 'type': 'numérique'},
            {'pattern': f'/{param}(', 'type': 'parenthèses'},
            {'pattern': f'/{param}/', 'type': 'chemin'},
            {'pattern': f'/{param}<<', 'type': 'dictionnaire'}
        ]
        
        for form in param_forms:
            pattern = form['pattern']
            start = context.find(pattern)
            if start != -1:
                st.write(f"Trouvé {pattern} à position relative {start} (absolue: {abs_pos + start})")
                pos = start + len(pattern)
                
                # Dump du contexte autour
                relative_context = context[max(0, start-10):min(len(context), start+50)]
                st.write(f"Contexte: ...{relative_context}...")
                
                if pattern.endswith('('):
                    end = context.find(')', pos)
                    if end != -1:
                        value = context[pos:end]
                        st.write(f"→ Valeur ({form['type']}): '{value}'")
                        st.write(f"→ Position valeur: {abs_pos + pos}-{abs_pos + end}")
                        return {
                            'value': value,
                            'start': abs_pos + pos,
                            'end': abs_pos + end,
                            'type': form['type']
                        }
                else:
                    value = ''
                    for i, char in enumerate(context[pos:pos+20]):
                        if char in '0123456789.':
                            value += char
                        else:
                            break
                    if value:
                        st.write(f"→ Valeur ({form['type']}): '{value}'")
                        st.write(f"→ Position valeur: {abs_pos + pos}-{abs_pos + pos + len(value)}")
                        return {
                            'value': value,
                            'start': abs_pos + pos,
                            'end': abs_pos + pos + len(value),
                            'type': form['type']
                        }
        st.write(f"❌ Paramètre {param} non trouvé")
        return None
    
    except Exception as e:
        st.error(f"Erreur lors de la recherche du paramètre {param}: {str(e)}")
        return None

def process_drm(buffer, positions):
    """Déprotection avec logging détaillé du DRM FileOpen."""
    st.write("\n=== DÉBUT TRAITEMENT DRM ===")
    processed_buffer = bytearray(buffer)
    
    for idx, pos in enumerate(positions):
        st.write(f"\n== Traitement occurrence {idx+1}/{len(positions)} à position {pos} ==")
        
        # Analyse d'un large contexte
        context_size = 1000
        context_start = max(0, pos - 50)
        context_end = min(len(buffer), pos + context_size)
        context = buffer[context_start:context_end].decode('latin-1', errors='ignore')
        
        st.write("\nAnalyse préliminaire:")
        dump_buffer(buffer, context_start, min(100, len(context)), "Premier bloc:")
        
        # Identifier structure FileOpen
        params = {}
        for param in ['Filter', 'V', 'Length', 'VEID', 'BUILD', 'SVID', 'DUID']:
            param_info = find_parameter(context, param, context_start)
            if param_info:
                params[param] = param_info
                st.write(f"\nTrouvé {param}:")
                st.write(f"  Valeur: {param_info['value']}")
                st.write(f"  Position: {param_info['start']}-{param_info['end']}")
                
                # Dump avant modification
                dump_buffer(buffer, param_info['start'], param_info['end'] - param_info['start'], 
                          f"Avant modification {param}:")
        
        # Modifications
        st.write("\n=== Application des modifications ===")
        
        # 1. SVID
        if 'SVID' in params:
            svid = params['SVID']
            replacement = b'NORBJ' + b' ' * (svid['end'] - svid['start'] - 5)
            st.write(f"\nModification SVID:")
            st.write(f"Position: {svid['start']}-{svid['end']}")
            dump_buffer(processed_buffer, svid['start'], len(replacement), "Avant:")
            for i, byte in enumerate(replacement):
                processed_buffer[svid['start'] + i] = byte
            dump_buffer(processed_buffer, svid['start'], len(replacement), "Après:")
        
        # 2. Paramètre V
        if 'V' in params:
            v_param = params['V']
            st.write(f"\nModification V:")
            st.write(f"Position: {v_param['start']}")
            dump_buffer(processed_buffer, v_param['start'], 1, "Avant:")
            processed_buffer[v_param['start']] = ord('0')
            dump_buffer(processed_buffer, v_param['start'], 1, "Après:")
        
        # 3. Length et contenu
        if 'Length' in params:
            length_param = params['Length']
            length = int(length_param['value'])
            st.write(f"\nTraitement Length ({length} bytes):")
            # Chercher endstream
            endstream_pos = context.find('endstream', length_param['end'] - context_start)
            if endstream_pos != -1:
                abs_endstream = context_start + endstream_pos
                st.write(f"Position endstream: {abs_endstream}")
                # Effacer contenu
                st.write(f"Effacement contenu de {length_param['end']} à {abs_endstream}")
                dump_buffer(processed_buffer, length_param['end'], 
                          min(50, abs_endstream - length_param['end']), "Avant:")
                for i in range(length_param['end'], abs_endstream):
                    processed_buffer[i] = 0
                dump_buffer(processed_buffer, length_param['end'], 
                          min(50, abs_endstream - length_param['end']), "Après:")
        
        st.write("\n=== Fin du traitement de cette occurrence ===\n")
    
    st.write("\n=== FIN TRAITEMENT DRM ===")
    return bytes(processed_buffer)

def analyze_pdf(file_bytes):
    """Analyse et déprotège le PDF avec logs détaillés."""
    try:
        st.write("=== DÉBUT ANALYSE PDF ===")
        st.write(f"Taille du fichier: {len(file_bytes)} bytes")
        st.write(f"Signature: {file_bytes[:8].hex()}")
        
        if file_bytes[:4] != b'%PDF':
            raise ValueError("Format de fichier non valide - Ce n'est pas un PDF")
        st.write("✓ En-tête PDF valide")
        
        content_latin = file_bytes.decode('latin-1', errors='ignore')
        matches = list(find_all_occurrences(content_latin, '/FOPN_foweb'))
        st.write(f"\nRecherche protection FileOpen:")
        st.write(f"Nombre d'occurrences: {len(matches)}")
        
        if matches:
            st.write("\n=== DÉTAIL DES OCCURRENCES ===")
            for i, pos in enumerate(matches):
                st.write(f"\n== Occurrence {i+1}/{len(matches)} ==")
                st.write(f"Position: {pos}")
                context_start = max(0, pos - 50)
                context = content_latin[context_start:pos + 200]
                st.write("Contexte:", context)
                dump_buffer(file_bytes, context_start, min(200, len(context)), "Premier bloc:")
        
        # Traitement DRM
        has_fileopen = len(matches) > 0
        if has_fileopen:
            st.write("\n=== DÉPROTECTION DRM ===")
            processed_buffer = process_drm(file_bytes, matches)
        else:
            processed_buffer = file_bytes
            
        st.write("\n=== EXTRACTION TEXTE ===")
        try:
            pdf_reader = PyPDF2.PdfReader(io.BytesIO(processed_buffer))
            text = ""
            st.write(f"Nombre de pages: {len(pdf_reader.pages)}")
            for i, page in enumerate(pdf_reader.pages):
                st.write(f"Extraction page {i+1}...")
                text += page.extract_text() + "\n"
            st.write("✓ Extraction réussie")
        except Exception as e:
            st.error(f"❌ Erreur extraction: {str(e)}")
            text = None
            
        # Infos finales
        drm_info = {
            'has_fileopen': has_fileopen,
            'type': 'FileOpen DRM' if has_fileopen else 'Pas de DRM FileOpen détecté',
            'filter': 'FOPN_foweb' if has_fileopen else 'N/A',
            'key_length': '5 bytes' if has_fileopen else 'N/A',
            'file_size': len(file_bytes),
            'size_kb': round(len(file_bytes) / 1024)
        }
        
        st.write("\n=== FIN ANALYSE PDF ===")
        return drm_info, processed_buffer, text
        
    except Exception as e:
        st.error(f"Erreur analyse PDF: {str(e)}")
        raise

def main():
    st.set_page_config(page_title="Analyse DRM FileOpen", layout="wide")
    st.title("Analyse DRM FileOpen")
    
    uploaded_files = st.file_uploader("Déposez vos PDF ici", type=['pdf'], accept_multiple_files=True)
    
    if uploaded_files:
        for uploaded_file in uploaded_files:
            try:
                st.write(f"\n=== TRAITEMENT {uploaded_file.name} ===")
                file_bytes = uploaded_file.getvalue()
                
                drm_info, processed_buffer, extracted_text = analyze_pdf(file_bytes)
                
                st.header(f"Résultats pour {uploaded_file.name}")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Type de protection", drm_info['type'])
                    st.metric("Filtre", drm_info['filter'])
                with col2:
                    st.metric("Taille de la clé", drm_info['key_length'])
                    st.metric("Taille du fichier", f"{drm_info['size_kb']} KB")
                
                if drm_info['has_fileopen']:
                    st.warning("Protection FileOpen détectée et déprotégée")
                    
                    if extracted_text:
                        with st.expander("Voir texte extrait"):
                            st.text_area("Contenu", extracted_text, height=200)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.download_button(
                                "📄 Télécharger texte",
                                extracted_text,
                                file_name=f"{uploaded_file.name}_text.txt",
                                mime="text/plain"
                            )
                        with col2:
                            st.download_button(
                                "📄 Télécharger PDF déprotégé",
                                processed_buffer,
                                file_name=f"{uploaded_file.name}_unprotected.pdf",
                                mime="application/pdf"
                            )
            
            except Exception as e:
                st.error(f"❌ Erreur lors du traitement de {uploaded_file.name}: {str(e)}")
                continue

if __name__ == "__main__":
    main()
