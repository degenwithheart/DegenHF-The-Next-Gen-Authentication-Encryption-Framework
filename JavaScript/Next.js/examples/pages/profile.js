// pages/profile.js
import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

export default function Profile() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    const verifyToken = async () => {
      const token = localStorage.getItem('token');

      if (!token) {
        router.push('/login');
        return;
      }

      try {
        const response = await fetch('/api/auth/verify', {
          headers: { Authorization: `Bearer ${token}` }
        });

        const data = await response.json();

        if (data.status === 'success') {
          setUser(data.user);
        } else {
          localStorage.removeItem('token');
          router.push('/login');
        }
      } catch (error) {
        localStorage.removeItem('token');
        router.push('/login');
      } finally {
        setLoading(false);
      }
    };

    verifyToken();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return null; // Will redirect
  }

  return (
    <div className="profile">
      <h1>Welcome {user.username}</h1>

      <div className="user-info">
        <p><strong>User ID:</strong> {user.id}</p>
        <p><strong>Username:</strong> {user.username}</p>
      </div>

      <button onClick={handleLogout} className="logout-btn">
        Logout
      </button>

      <style jsx>{`
        .profile {
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }

        .user-info {
          background-color: #f9f9f9;
          padding: 20px;
          border-radius: 8px;
          margin: 20px 0;
        }

        .user-info p {
          margin: 10px 0;
          font-size: 16px;
        }

        .logout-btn {
          padding: 10px 20px;
          background-color: #dc3545;
          color: white;
          border: none;
          border-radius: 4px;
          font-size: 16px;
          cursor: pointer;
        }

        .logout-btn:hover {
          background-color: #c82333;
        }
      `}</style>
    </div>
  );
}