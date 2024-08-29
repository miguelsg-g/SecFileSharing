import React, { useState } from 'react';
import axiosInstance from '../services/axiosInterceptors';
import '../styles/CreateGroupForm.css';

const CreateGroupForm = ({ onSuccess }) => {
    const [groupName, setGroupName] = useState('');
    const [message, setMessage] = useState('');

    const handleSubmit = async (event) => {
        event.preventDefault();
        try {
            // Send a POST request to the backend containing the group name and the owner of the group
            const response = await axiosInstance.post('/create_group/', { group_name: groupName });
            setMessage(response.data.message);
            setGroupName(''); // Clear the input field  
            if (onSuccess) onSuccess();
        } catch (error) {
            console.error('Error creating group:', error);
            setMessage('Error creating group.');
        }
    };
    // htmlFor is used to associate the label with the input field
    return (
        <div className="create-group-form">
            <h2>Create Group</h2>
            <form onSubmit={handleSubmit}>
                <div className="form-group">
                    <label htmlFor="group_name">Group Name</label>
                    <input
                        type="text"
                        id="group_name"
                        value={groupName}
                        onChange={(e) => setGroupName(e.target.value)}
                        required
                    />
                </div>
                <button type="submit" className="btn btn-primary">Create Group</button>
            </form>
            {message && <div className="alert">{message}</div>}
        </div>
    );
};

export default CreateGroupForm;