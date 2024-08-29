// AddMembers.js
import React, { useState, useEffect } from 'react';
import axiosInstance from '../services/axiosInterceptors';
import '../styles/AddMembers.css';

const AddMembers = ({ groupId, onSuccess }) => {
    const [users, setUsers] = useState([]);
    const [selectedMembers, setSelectedMembers] = useState([]);
    const [message, setMessage] = useState('');

    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await axiosInstance.get(`/group/${groupId}/users/`);
                setUsers(response.data);
            } catch (error) {
                console.error('Error fetching users:', error);
            }
        };

        fetchUsers();
    }, [groupId]);

    const handleSelectMember = (username) => {
        setSelectedMembers((prevMembers) => {
            if (prevMembers.includes(username)) {
                return prevMembers.filter(member => member !== username);
            } else {
                return [...prevMembers, username];
            }
        });
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        try {
            const response = await axiosInstance.post(`/group/${groupId}/add_members/`, { members: selectedMembers });
            setMessage(response.data.message);
            if (onSuccess) onSuccess();
        } catch (error) {
            console.error('Error adding members:', error);
            setMessage('Error adding members.');
        }
    };

    return (
        <div className="add-members-form">
            <h2>Add Members</h2>
            <form onSubmit={handleSubmit}>
                <ul className="user-list">
                    {users.map(user => (
                        <li key={user.id} className="user-item">
                            <label>
                                <input
                                    type="checkbox"
                                    value={user.username}
                                    onChange={() => handleSelectMember(user.username)}
                                    checked={selectedMembers.includes(user.username)}
                                />
                                {user.username}
                            </label>
                        </li>
                    ))}
                </ul>
                <button type="submit" className="btn btn-primary">Add Members</button>
            </form>
            {message && <div className="alert">{message}</div>}
        </div>
    );
};

export default AddMembers;