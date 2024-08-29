// UploadFileForm.js
import React, { useState, useEffect } from 'react';
import axiosInstance from '../services/axiosInterceptors';
import '../styles/UploadFileForm.css';

const UploadFileForm = ({ onSuccess }) => {
    const [file, setFile] = useState(null);
    const [group, setGroup] = useState('');
    const [ciphered, setCiphered] = useState(false);
    const [groups, setGroups] = useState([]);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchGroups = async () => {
            try {
                const response = await axiosInstance.get('/upload_file/');
                setGroups(response.data.groups);
            } catch (err) {
                setError('Error fetching groups: ' + err.message);
            }
        };
        fetchGroups();
    }, []);

    const handleFileChange = (event) => {
        setFile(event.target.files[0]);
    };

    const handleGroupChange = (event) => {
        setGroup(event.target.value);
    };

    const handleCipheredChange = (event) => {
        setCiphered(event.target.checked);
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        const formData = new FormData();
        formData.append('file', file);
        formData.append('group', group);
        formData.append('ciphered', ciphered);

        try {
            await axiosInstance.post('/upload_file/', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            });
            onSuccess();
        } catch (err) {
            setError('Error uploading file: ' + err.message);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="upload-file-form">
            <h2>Subir un Nuevo Fichero</h2>
            <div className="form-group">
                <label htmlFor="file">Fichero</label>
                <input type="file" id="file" onChange={handleFileChange} required />
            </div>
            <div className="form-group">
                <label htmlFor="group">Grupo</label>
                <select id="group" value={group} onChange={handleGroupChange} required>
                    <option value="" disabled>Seleccione un grupo</option>
                    {groups.map(g => (
                        <option key={g.id} value={g.group_name}>{g.group_name}</option>
                    ))}
                </select>
            </div>
            <div className="form-group">
                <label htmlFor="ciphered">Cifrado</label>
                <input type="checkbox" id="ciphered" checked={ciphered} onChange={handleCipheredChange} />
            </div>
            <button type="submit" className="btn btn-primary">Subir</button>
            {error && <div className="alert">{error}</div>}
        </form>
    );
};

export default UploadFileForm;