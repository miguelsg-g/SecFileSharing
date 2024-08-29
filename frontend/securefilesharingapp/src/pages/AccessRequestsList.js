import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
//import { useNavigate } from 'react-router-dom';
import axiosInstance from '../services/axiosInterceptors';
import Base from '../components/Base';
import '../styles/AccessRequestsList.css';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
// importamos el icono de una cruz para el botón de rechazar
import { faTimes } from '@fortawesome/free-solid-svg-icons';
import { format } from 'date-fns';

const AccessRequests = () => {
    const { groupId } = useParams();
    const [requests, setRequests] = useState([]);
    const [user, setUser] = useState(null);
    const [group, setGroup] = useState(null);
    //const navigate = useNavigate();
    const [error, setError] = useState(null);


    useEffect(() => {
        const fetchAccessRequests = async () => {
            try {
                const response = await axiosInstance.get(`/group/${groupId}/access_requests/`);
                setRequests(response.data.requests);
                setUser(response.data.user);
                setGroup(response.data.group);
                console.log("Requests:", response.data.requests);
            } catch (err) {
                setError('Error fetching access requests: ' + err.message);
            }
        };

        fetchAccessRequests();
    }, [groupId]);

    const handleRejectRequest = async (requestId) => {
        try {
            await axiosInstance.post(`/handle_access_request/${requestId}/rejected/`);
            setRequests(requests.filter(request => request.id !== requestId));
        } catch (err) {
            setError('Error rejecting request: ' + err.message);
        }
    };

    const groupedRequests = requests.reduce((acc, request) => {
        const status = request.status.toLowerCase(); // Convertir el estado a minúsculas
        if (status === 'pending') {
            return { ...acc, pending: [...acc.pending, request] };
        } else if (status === 'accepted') {
            return { ...acc, accepted: [...acc.accepted, request] };
        } else if (status === 'rejected') {
            return { ...acc, rejected: [...acc.rejected, request] };
        }
        return acc;
    }, { pending: [], accepted: [], rejected: [] });

    const formatDate = (dateString) => {
        const date = new Date(dateString);
        return format(date, 'dd/MM/yyyy HH:mm');
    };

    if (error) {
        return <div>Error: {error}</div>;
    }

    if (!user || !group) {
        return <div>Loading...</div>;
    }

    // Imprimir en consola el grupo y las solicitudes agrupadas
    console.log("Group:", group);
    console.log("Grouped Requests:", groupedRequests);

    return (
        <Base user={user}>
            <div className="access-requests-container">
                <h2>Solicitudes de acceso para el grupo {group.group_name}</h2>

                <h3>Pending Requests</h3>
                {groupedRequests.pending.length > 0 ? (
                    <ul>
                        {groupedRequests.pending.map(request => (
                            <li key={request.id} className="access-request-item">
                                <span>
                                <p className="request-info">
                                    Solicitante: {request.requester}
                                </p>
                                <p className="request-info">
                                    Fecha de la Solicitud: {formatDate(request.created_at)}
                                </p>
                                </span>
                                <button onClick={() => handleRejectRequest(request.id)} className='reject-button'><FontAwesomeIcon icon={faTimes} /> Rechazar</button>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p>No hay solicitudes pendientes.</p>
                )}

                <h3>Accepted Requests</h3>
                {/* <!-- Mostrar el nombre del solicitante y la fecha de creación de la solicitud, la fecha con formato dd/mm/yyyy hh:mm --> */}
                {/* span es una etiqueta de línea en línea que se utiliza para agrupar elementos en línea en un documento HTML */}
                {groupedRequests.accepted.length > 0 ? (
                    <ul>
                        {groupedRequests.accepted.map(request => (
                            <li key={request.id} className="access-request-item">
                                <span>
                                <p className="request-info">
                                    Solicitante: {request.requester}
                                </p>
                                <p className="request-info">
                                    Fecha de la Solicitud: {formatDate(request.created_at)}
                                </p>
                                </span>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p>No hay aún ninguna petición aceptada.</p>
                )}

                <h3>Rejected Requests</h3>
                {groupedRequests.rejected.length > 0 ? (
                    <ul>
                        {groupedRequests.rejected.map(request => (
                            <li key={request.id} className="access-request-item">
                                <span>
                                <p className="request-info">
                                    Solicitante: {request.requester}
                                </p>
                                <p className="request-info">
                                    Fecha de la Solicitud: {formatDate(request.created_at)}
                                </p>
                                </span>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p>No hay aún ninguna petición rechazada.</p>
                )}
                <Link to={`/group/${groupId}`} className="back-link">Volver al grupo</Link>
            </div>
        </Base>
    );
};

export default AccessRequests;
