// import logo from 'C:\Users\migue\OneDrive\Documentos\MUIT\TFM\SecFileSharingApp\SecFileSharingApp\static\SecFileSharingApp\favicon.ico';
import './App.css';
import React from 'react';//, {useEffect}
import { Route, Routes } from 'react-router-dom';
import Register from './pages/Register';
import Login from './pages/Login';
import VerifyEmail from './pages/VerifyEmail';
import Dashboard from './pages/Dashboard';
import PersonalPage from './pages/PersonalPage';
import GroupDetail from './pages/GroupDetail';
import AccessRequestsList from './pages/AccessRequestsList';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import PrivateRoute from './utils/PrivateRoute';

// import { AuthProvider } from './contexts/authContext'
//import authService from './services/authService';

function App() {
  return (
    <div className="App">
        <Routes>
            {/* <AuthProvider> */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/register" element={<Register />} />
            <Route path="/login" element={<Login />} />
            <Route path="/verify-email/:uid/:token" element={<VerifyEmail />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/personal_page" element={<PersonalPage />} />
            <Route path="/group/:groupId" element={<PrivateRoute><GroupDetail /></PrivateRoute>} />
            <Route path="/group/:groupId/access_requests" element={<PrivateRoute> <AccessRequestsList /> </PrivateRoute>} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password/:uidb64/:token" element={ <ResetPassword />} />
            <Route path="*" element={<h1>Not Found</h1>} />
            {/* Otras rutas */}
        </Routes>
        {/* </AuthProvider> */}
        
    </div>
  );
}

export default App;
