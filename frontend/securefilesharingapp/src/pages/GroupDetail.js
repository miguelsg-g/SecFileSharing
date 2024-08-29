import React, { useEffect, useState } from 'react';
import { useParams, Link, Navigate } from 'react-router-dom';
import axiosInstance from '../services/axiosInterceptors';
import Base from '../components/Base';
import '../styles/GroupDetail.css';
import Modal from '../components/Modal';
import UploadFileForm from '../components/UploadFileForm';
import AddMembers from '../components/AddMembers';
import FileItem from '../components/FileItem';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUpload, faTrashAlt, faUserAlt } from '@fortawesome/free-solid-svg-icons';
import download from 'downloadjs';
// import { useNavigate } from 'react-router-dom';
const GroupDetail = () => {
    const { groupId } = useParams();
    const [group, setGroup] = useState(null);
    const [files, setFiles] = useState([]);
    const [canUpload, setCanUpload] = useState(false);
    const [isMember, setIsMember] = useState(false);
    const [isPersonalGroup, setIsPersonalGroup] = useState(false);
    const [user, setUser] = useState(null);
    const [error, setError] = useState(null);
    const [showUploadModal, setShowUploadModal] = useState(false);
    const [showAddMembersModal, setShowAddMembersModal] = useState(false);
    // const navigate = useNavigate();

    useEffect(() => {
        const fetchGroupDetails = async () => {
            try {
                const response = await axiosInstance.get(`/group/${groupId}/`);
                if (response.status === 404) {
                    setError('Group not found');
                    return;
                }
                if (response.status === 403) {
                    setError('You do not have permission to access this group');
                    return;
                }
                setGroup(response.data.group);
                setFiles(response.data.files);
                setCanUpload(response.data.can_upload);
                setIsMember(response.data.is_member);
                setIsPersonalGroup(response.data.is_personal_group);
                setUser(response.data.user);
            } catch (err) {
                setError('Error fetching group details: ' + err.message);
            }
        };

        fetchGroupDetails();
    }, [groupId]);

    const handleDeleteFile = async (fileId) => {
        if (window.confirm('¿Estás seguro de que quieres eliminar este archivo?')) {
            try {
                await axiosInstance.delete(`/delete_file/${fileId}/`);
                setFiles(files.filter(file => file.id !== fileId));
            } catch (err) {
                setError('Error deleting file: ' + err.message);
            }
        }
    };

    const handleDownloadFile = async (fileId) => {
        try {
            const response = await axiosInstance.get(`/download_file/${fileId}/`, { responseType: 'blob' });
            let contentDisposition = response.headers['content-disposition'];
            console.log(contentDisposition);
            console.log(response.headers);
            let fileName = 'file';

            if (contentDisposition) {
                contentDisposition = decodeURIComponent(contentDisposition);
                const fileNameMatch = contentDisposition.match(/filename="?(.+)"?/); // extraemos el nombre del archivo de la cabecera content-disposition
                if (fileNameMatch && fileNameMatch.length === 2) {
                    fileName = fileNameMatch[1].replace(/['"]/g, ''); // Eliminar comillas del nombre del archivo
                    console.log('Filename:', fileName);
                }
            }
            fileName = fileName.replace(/[^a-zA-Z0-9.\-_]/g, '_');
            console.log(fileName);
            // Descargar el archivo con un método alternativo a saveAs, ya que este último no funciona en Safari y en Firefox está modificando el nombre del archivo añadiendo un _ al final (por ejemplo, si el archivo se llama 'file.pdf', se descarga como 'file.pdf_' en Firefox)
            // en su lugar, usamos la librería downloadjs que funciona en todos los navegadores
            if (window.navigator && window.navigator.msSaveOrOpenBlob) {
                // Para IE y Edge
                window.navigator.msSaveOrOpenBlob(response.data, fileName);
                return;
            }
            download(response.data, fileName, response.headers['content-type']); // se descarga el archivo con el nombre original y el tipo de contenido correcto

            console.log('File downloaded: ', fileName);
        } catch (err) {
            setError('Error downloading file: ' + err.message);
        }
    };

    const confirmDeletion = (groupId, memberId) => {
        if (window.confirm("¿Estás seguro de que quieres eliminar a este miembro del grupo?")) {
            axiosInstance.delete(`/delete_member/${groupId}/${memberId}/`)
                .then(() => {
                    setGroup(prevGroup => ({
                        ...prevGroup,
                        members: prevGroup.members.filter(member => member.id !== memberId)
                    }));
                })
                .catch(error => {
                    console.error('Error deleting member:', error);
                });
        }
    };

    const handleUploadModalOpen = () => {
        setShowUploadModal(true);
    };

    const handleUploadModalClose = () => {
        setShowUploadModal(false);
        axiosInstance.get(`/group/${groupId}/`).then(response => setFiles(response.data.files));
    };

    const handleAddMembersModalOpen = () => {
        setShowAddMembersModal(true);
    };

    const handleAddMembersModalClose = () => {
        setShowAddMembersModal(false);
        // Refresh members after adding
        axiosInstance.get(`/group/${groupId}/`).then(response => setGroup(response.data.group));
    };

    if (error) {
        return <div>Error fetching data: {error}</div>;
    }

    if (!group || !user) {
        return <div>Loading...</div>;
    }

    return (
        <Base user={user}>
            {!isMember && !canUpload && !isPersonalGroup && (
                console.log('No eres miembro del grupo'),
                <Navigate to="/" />
            )}
            <div className="group-detail-container">
                <h1>{group.group_name}</h1>
                <h2>Detalles del grupo</h2>
                <p>Propietario: {group.owner}</p>
                {isPersonalGroup && (
                    <p>Este es tu grupo personal para datos privados.</p>
                )}
                {isMember && (
                    <p>Eres miembro de este grupo.</p>
                )}
                {(!isPersonalGroup && group.members.length !== 0 && canUpload) && (
                    <div className="members-section">
                        <h3>Miembros: </h3>
                        <ul className="member-list">
                            {group.members.map(member => (
                                <li key={member.id} className="member-item">
                                    {member.user}
                                    {group.owner !== member.user && (
                                        <button className="remove-member-button" title="Eliminar a este miembro del grupo" onClick={() => confirmDeletion(group.id, member.id)}>  <FontAwesomeIcon icon={faTrashAlt} />  </button>
                                    )}
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
                <div className="group-files">
                    <h3>Ficheros compartidos</h3>
                    {files.length > 0 ? (
                        <ul className="file-list">
                            {files.map(file => (
                                <FileItem
                                    key={file.id}
                                    file={file}
                                    groupId={group.id}
                                    canUpload={canUpload}
                                    isMember={isMember}
                                    onDelete={handleDeleteFile}
                                    onDownload={handleDownloadFile}
                                />
                            ))}
                        </ul>
                    ) : (
                        <div>No hay ficheros compartidos.</div>
                    )}
                </div>
                
                {canUpload && (
                    <div className="upload-section">
                        <button className="upload-button" onClick={handleUploadModalOpen}> 
                            <FontAwesomeIcon icon={faUpload} /> Subir fichero
                        </button>
                    </div>
                )}

                {(canUpload && !isPersonalGroup) && (
                    <div>
                        <div>
                            <h2>Agregar miembros</h2>
                            <button className="add-members-btn" onClick={handleAddMembersModalOpen}><FontAwesomeIcon icon={faUserAlt} /> Add</button>
                        </div>
                        <div>
                        <h2>Solicitudes de acceso</h2>
                            <Link to={`/group/${group.id}/access_requests`} className='access-requests-list-link'>Consultar solicitudes de acceso</Link>
                        </div>
                    </div>
                )}
            </div>
            <Modal show={showUploadModal} handleClose={handleUploadModalClose}>
                <UploadFileForm onSuccess={handleUploadModalClose} groupId={groupId} />
            </Modal>
            <Modal show={showAddMembersModal} handleClose={handleAddMembersModalClose}>
                <AddMembers onSuccess={handleAddMembersModalClose} groupId={groupId} />
            </Modal>
        </Base>
    );
};

export default GroupDetail;










// import React, { useEffect, useState } from 'react';
// import { useParams, Link } from 'react-router-dom';
// import axiosInstance from '../services/axiosInterceptors';
// import Base from '../components/Base';
// import './GroupDetail.css';
// import Modal from '../components/Modal';
// import UploadFileForm from '../components/UploadFileForm';
// import FileItem from '../components/FileItem';
// import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
// import { faFileWord, faFilePdf, faFileAlt, faTrashAlt, faUpload } from '@fortawesome/free-solid-svg-icons';

// const GroupDetail = () => {
//     const { groupId } = useParams();
//     const [group, setGroup] = useState(null);
//     const [files, setFiles] = useState([]);
//     const [canUpload, setCanUpload] = useState(false);
//     const [isMember, setIsMember] = useState(false);
//     const [isPersonalGroup, setIsPersonalGroup] = useState(false);
//     const [user, setUser] = useState(null);
//     const [error, setError] = useState(null);
//     const [showUploadModal, setShowUploadModal] = useState(false);

//     useEffect(() => {
//         const fetchGroupDetails = async () => {
//             try {
//                 const response = await axiosInstance.get(`/group/${groupId}/`);
//                 setGroup(response.data.group);
//                 setFiles(response.data.files);
//                 setCanUpload(response.data.can_upload);
//                 setIsMember(response.data.is_member);
//                 setIsPersonalGroup(response.data.is_personal_group);
//                 setUser(response.data.user);
//             } catch (err) {
//                 setError('Error fetching group details: ' + err.message);
//             }
//         };

//         fetchGroupDetails();
//     }, [groupId]);

//     const handleDeleteFile = async (fileId) => {
//         if (window.confirm('¿Estás seguro de que quieres eliminar este archivo?')) {
//             try {
//                 await axiosInstance.delete(`/delete_file/${fileId}/`);
//                 setFiles(files.filter(file => file.id !== fileId));
//             } catch (err) {
//                 setError('Error deleting file: ' + err.message);
//             }
//         }
//     };

//     const handleDownloadFile = (fileId) => {
//         axiosInstance.get(`/download_file/${fileId}/`, { responseType: 'blob' })
//             .then(response => {
//                 const url = window.URL.createObjectURL(new Blob([response.data]));
//                 const link = document.createElement('a');
//                 link.href = url;
//                 link.setAttribute('download', response.headers['content-disposition'].split('filename=')[1]);
//                 document.body.appendChild(link);
//                 link.click();
//                 document.body.removeChild(link);
//             })
//             .catch(err => setError('Error downloading file: ' + err.message));
//             // console.log('Error downloading file: ' + err.message);
//     };

//     if (error) {
//         return <div>Error fetching data: {error.message}</div>;
//     }

//     if (!group || !user) {
//         return <div>Loading...</div>;
//     }

//     const confirmDeletion = (groupId, memberId) => {
//         if (window.confirm("¿Estás seguro de que quieres eliminar a este miembro del grupo?")) {
//             axiosInstance.delete(`/delete_member/${groupId}/${memberId}/`)
//                 .then(() => {
//                     setGroup(prevGroup => ({
//                         ...prevGroup,
//                         members: prevGroup.members.filter(member => member.id !== memberId)
//                     }));
//                 })
//                 .catch(error => {
//                     console.error('Error deleting member:', error);
//                 });
//         }
//     };

//     const getIconForFileType = (fileName) => {
//         const extension = fileName.split('.').pop().toLowerCase();
//         switch (extension) {
//             case 'pdf':
//                 return faFilePdf;
//             case 'doc':
//             case 'docx':
//                 return faFileWord;
//             // Puedes agregar más casos para diferentes tipos de archivo
//             default:
//                 return faFileAlt;
//         }
//     };

//     const handleUploadModalOpen = () => {
//         setShowUploadModal(true);
//     };

//     const handleUploadModalClose = () => {
//         setShowUploadModal(false);
//         // Refresh files after uploading
//         axiosInstance.get(`/group/${groupId}/`).then(response => setFiles(response.data.files));
//     };


//     return (
//         <Base user={user}>
//             <div className="group-detail-container">
//                 <h1>{group.group_name}</h1>
//                 <h2>Detalles del grupo</h2>
//                 <p>Propietario: {group.owner.username}</p>
//                 {isPersonalGroup && (
//                     <p>This is your personal group for private data.</p>
//                 )}
//                 {(!isPersonalGroup && group.members.length !== 0 && canUpload) && (
//                     <div className="members-section">
//                         <h3>Miembros: </h3>
//                         <ul className="member-list">
//                             {group.members.map(member => (
//                                 <li key={member.id} className="member-item">
//                                     {member.user}
//                                     {group.owner !== member.user && (
//                                         <button className="remove-member-button" onClick={() => confirmDeletion(group.id, member.id)}>  Eliminar </button>
//                                     )}
//                                 </li>
//                             ))}
//                         </ul>
//                     </div>
//                 )}
//                 <div className="group-files">
//                 <h3>Ficheros compartidos</h3>
//                     {files.length > 0 ? (
//                         <ul className="file-list">
//                             {files.map(file => (
//                                 <div key={file.id} className="file-item">
//                                     {(canUpload || isMember) ? (
//                                         <button onClick={() => handleDownloadFile(file.id)} className="file-download-btn"> <FontAwesomeIcon icon={getIconForFileType(file.file_name)} /> {file.file_name} </button>
//                                     ) : (
//                                         <p>{file.file_name}</p>
//                                     )}
//                                     {canUpload && (
//                                         <button onClick={() => handleDeleteFile(file.id)} className="file-delete-btn">
//                                             <FontAwesomeIcon icon={faTrashAlt} /> 
//                                         </button>
//                                     )}
//                                 </div>
//                             ))}
//                         </ul>
//                     ) : (
//                         <div>No hay ficheros compartidos.</div>
//                     )}
//                 </div>
                
//                 {canUpload && (
//                     <div className="upload-section">
//                         <button className="upload-button" onClick={ handleUploadModalOpen}> <FontAwesomeIcon icon={faUpload} /> 
//                              Subir fichero</button>
//                     </div>
//                 )}

//                 {(canUpload && !isPersonalGroup) && (
//                     <div>
//                         <h2>Agregar miembros</h2>
//                         <p>
//                             <a href={`/add_group_members/${group.id}`}>
//                                 <button type="button">Add</button>
//                             </a>
//                         </p>
//                     </div>
//                 )}
//                 {group.owner.username === user.username && (
//                     <div>
//                         <h2>Eliminar fichero</h2>
//                         <ul>
//                             {files.map(file => (
//                                 <div key={file.id}>
//                                     <Link href={`/delete_file/${file.id}`}>{file.file_name}</Link>
//                                 </div>
//                             ))}
//                         </ul>
//                     </div>
//                 )}
//                 {group.owner.username === user.username && (
//                     <div>
//                         <h2>Eliminar miembros</h2>
//                         {group.members.map(member => (
//                             <div key={member.id}>
//                                 <button type="button" onClick={() => confirmDeletion(group.id, member.id)}>
//                                     Eliminar {member.user.username}
//                                 </button>
//                             </div>
//                         ))}
//                     </div>
//                 )}
//             </div>
//             <Modal show={showUploadModal} handleClose={handleUploadModalClose}>
//                 <UploadFileForm onSuccess={handleUploadModalClose} groupId={groupId} />
//             </Modal>
//         </Base>
//     );
// };

// export default GroupDetail;