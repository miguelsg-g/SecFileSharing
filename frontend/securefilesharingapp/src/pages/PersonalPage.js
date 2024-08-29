import React, { useEffect, useState } from 'react';
import getBackendData from '../services/getBackendData';
import '../styles/PersonalPage.css';
import Base from '../components/Base';
import Modal from '../components/Modal';
import CreateGroupForm from '../components/CreateGroupForm';
import axiosInstance from '../services/axiosInterceptors';
import { Link } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTrashAlt, faUpload } from '@fortawesome/free-solid-svg-icons';
import UploadFileForm from '../components/UploadFileForm';

const PersonalPage = () => {
    const [userGroups, setUserGroups] = useState([]);
    const [userOwnedGroups, setUserOwnedGroups] = useState([]);
    const [user, setUser] = useState(null);
    const [error, setError] = useState(null);
    const [showModal, setShowModal] = useState(false);
    // const [showCreateGroupModal, setShowCreateGroupModal] = useState(false);
    const [showUploadFileModal, setShowUploadFileModal] = useState(false);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const data = await getBackendData.getPersonalPageData();
                setUserGroups(data.user_groups);
                setUserOwnedGroups(data.user_owned_groups);
                setUser(data.user);
            } catch (err) {
                setError('Error fetching data: ' + err.message);
            }
        };

        fetchData();
    }, []);

    const handleOpenModal = () => {
        setShowModal(true);
    };

    const handleCloseModal = () => {
        setShowModal(false);
        // Optionally refresh the user data to show the new group
        axiosInstance.get('/personal_page/').then(response => setUserOwnedGroups(response.data.user_owned_groups));
    };

    const handleOpenUploadFileModal = () => {
        setShowUploadFileModal(true);
    };

    const handleCloseUploadFileModal = () => {
        setShowUploadFileModal(false);
        axiosInstance.get('/personal_page/').then(response => setUserOwnedGroups(response.data.user_owned_groups));
    };

    const confirmDeletion = async (groupId) => {
        const confirm = window.confirm('¿Estás seguro de que quieres eliminar este grupo?');
        if (confirm) {
            try {
                const response = await axiosInstance.delete(`/delete_group/${groupId}/`);
                if (response.status === 200) {
                    setUserOwnedGroups(userOwnedGroups.filter(group => group.id !== groupId));
                } 
                else {
                    setError(response.data.error || 'Error eliminando el grupo');
                }
            } catch (error) {
                console.error('Error deleting group:', error);
                setError(error.response?.data?.error || 'Error eliminando el grupo: ' + error.message);
            }
        }
    };

    if (error) {
        return <div>Error fetching data: {error.message}</div>;
    }

    if (!user) {
        return <div>Loading...</div>;
    }

    return (
        <Base user={user}>
            <div className="personal-page-container">
                <div className="page-header">
                    <h2>Mi Página Personal</h2>
                </div>
                <h3>Grupos compartidos</h3>
                <ul className="group-list">
                    {userGroups.length > 0 ? (
                        userGroups.map(group => (
                            <li key={group.id} className="group-item">
                                <a href={`/group/${group.id}`} className="group-link" title="Enlace al grupo">
                                    {group.group_name}
                                </a>
                            </li>
                        ))
                    ) : (
                        <p>No hay grupos compartidos contigo.</p>
                    )}
                </ul>
                <h3>Mis Grupos</h3>
                <ul className="group-list">
                    {userOwnedGroups.length > 0 ? (
                        userOwnedGroups.map(group => (
                            <li key={group.id} className="group-item">
                                <a href={`/group/${group.id}`} className="group-link">
                                    {group.group_name}
                                </a>
                                {group.group_name !== `${user.username}_personal_data` && (
                                    <button className="delete-button" onClick={() => confirmDeletion(group.id)} title="Eliminar Grupo"> <FontAwesomeIcon icon={faTrashAlt} /> </button>
                                )}
                            </li>
                        ))
                    ) : (
                        <p>No tienes grupos propios.</p>
                    )}
                </ul>
                <div className="links-container">
                    <Link href="#" onClick={handleOpenModal} className="create-group-link">Crear Grupo</Link>
                    <Link className="upload-file-link" onClick={handleOpenUploadFileModal}> <FontAwesomeIcon icon={faUpload} /> Subir Fichero</Link>
                </div>
            </div>
            {error && <div className="error-message">{error}</div>}
            <Modal show={showModal} handleClose={handleCloseModal}>
                <CreateGroupForm onSuccess={handleCloseModal} />
            </Modal>
            <Modal show={showUploadFileModal} handleClose={handleCloseUploadFileModal}>
                <UploadFileForm onSuccess={handleCloseUploadFileModal} />
            </Modal>
        </Base>
    );
};

export default PersonalPage;