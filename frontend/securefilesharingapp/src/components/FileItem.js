import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faFileWord, faFilePdf, faFileExcel, faFileAlt, faTrashAlt, faDownload } from '@fortawesome/free-solid-svg-icons';

const FileItem = ({ file, canUpload, isMember, onDelete, onDownload }) => {
    const getIconForFileType = (fileName) => {
        const extension = fileName.split('.').pop().toLowerCase();
        switch (extension) {
            case 'pdf':
                return faFilePdf;
            case 'doc':
            case 'docx':
                return faFileWord;
            case 'xls':
            case 'xlsx':
                return faFileExcel;
            default:
                return faFileAlt;
        }
    };

    return (
        <li className="file-item">
            {isMember && (
                <>
                    <FontAwesomeIcon icon={getIconForFileType(file.file_name)} /> {file.file_name} 
                    <button onClick={() => onDownload(file.id)} className="file-download-btn">
                        <FontAwesomeIcon icon={faDownload} />
                    </button>
                </>
            )}
            {canUpload && (
                <div className="file-name">
                    <FontAwesomeIcon icon={getIconForFileType(file.file_name)} /> {file.file_name} 
                    <button onClick={() => onDownload(file.id)} className="file-download-btn" title= "Download file">
                        <FontAwesomeIcon icon={faDownload} />
                    </button>
                    <button onClick={() => onDelete(file.id)} className="file-delete-btn" title="Delete file">
                        <FontAwesomeIcon icon={faTrashAlt} />
                    </button>
                </div>
            )}
        </li>
    );
};

export default FileItem;
