import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Base from '../components/Base';
import getBackendData from '../services/getBackendData';
import RequestAccess from '../components/RequestAccess';
import '../styles/Dashboard.css';  // Asegúrate de importar el archivo CSS
import Modal from '../components/Modal';

const Dashboard = () => {
    const [groups, setGroups] = useState([]);
    const [user, setUser] = useState({});
    const navigate = useNavigate();
    const [selectedGroup, setSelectedGroup] = useState(null);
    const [showModal, setShowModal] = useState(false);
    const [requestAccessMessage, setRequestAccessMessage] = useState('');
    const filteredGroups = groups.filter(group => !(group.group_name.endsWith('_personal_data') && !(group.group_name === `${user.username}_personal_data`)));  // Filtrar los grupos personales de otros usuarios
    useEffect(() => {
        const fetchUserData = async () => {
            try {
                const data = await getBackendData.getUserData();
                setUser(data.user);
                const transformedGroups = data.groups.map(group => ({
                    ...group,
                    members: group.members.map(member => member.user)
                }));
                setGroups(transformedGroups);
            } catch (error) {
                console.error('Error fetching user data:', error);
                navigate('/login');  // Redirigir a la página de inicio de sesión si hay un error
            }
        };

        fetchUserData();
    }, [navigate]);

    if (!user.id) {
        // Mostrar una indicación de carga mientras se obtienen los datos del usuario
        return <div>Loading...</div>;
    }

    const handleRequestAccess = (groupId) => {
        setSelectedGroup(groupId);
        setShowModal(true);
    };

    const handleAccessSuccess = (message) => {
        setRequestAccessMessage(message);
        setSelectedGroup(null);
        setShowModal(false);
    };

    const handleModalClose = () => {
        setSelectedGroup(null);
        setShowModal(false);
    };
    // No se deben mostrar los grupos personales de otros usuarios, que tiene el formato username_personal_data. Para ello, comprobamos que el nombre del grupo no termine con "_personal_data" y empiece con otro nombre que no sea el del usuario actual.
    return (
        <Base user={user}>
            <div className="page-header">
                <h2 className="page-header h2">Dashboard</h2> 
            </div>
            <div className="actions">
                    <p className="user-greeting">Hola, {user.username}</p>
            </div>
            <div className="dashboard-container">
                <h3>Groups List</h3>
                <ul className="group-list">
                    {filteredGroups.map((group) => (
                        <li key={group.id} className="group-item">
                            {user.username !== group.owner && !group.members.includes(user.username) ? (
                                <Link to="#" title="Request access" onClick={() => handleRequestAccess(group.id)} className="group-link">
                                    <span className="group-icon">👥</span>
                                    {group.group_name}
                                </Link>
                            ) : (
                                <Link to={`/group/${group.id}`} className="group-link">
                                    <span className="group-icon">👥</span>
                                    {group.group_name}
                                </Link>
                            )}
                        </li>
                    ))}
                </ul>
                {showModal && (
                    <Modal show={showModal} handleClose={handleModalClose}>
                        <RequestAccess groupId={selectedGroup} onSuccess={handleAccessSuccess} />
                    </Modal>
                )}
                {requestAccessMessage && (
                    <div className='access-message'>
                        {requestAccessMessage}
                    </div>
                )}
            </div>
        </Base>
    );
};

export default Dashboard;