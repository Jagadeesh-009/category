import { Link, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import axios from 'axios';
import './index.css';

const SignUp = () => {
  const [valus, setValues] = useState({
    username: '',
    email: '',
    password: '',
  });
  const [error, setError] = useState('');
  const navigate = useNavigate();
  axios.defaults.withCredentials = true;

  const handleSubmit = (event) => {
    event.preventDefault();
    axios
      .post('http://localhost:8081/signup', valus)
      .then((res) => {
        if (res.data.status === 'success') {
          navigate('/login');
        } else {
          setError(res.data.error);
          alert(res.data.error || 'Error signing up');
        }
      })
      .catch((err) => {
        console.log(err);
      });
  };

  return (
    <div className='container d-flex align-items-center justify-content-center flex-column vh-100'>
      <div className='login-page'>
        <form className='login-form p-5' onSubmit={handleSubmit}>
          <h1 className='text-center mb-2'>SignUp</h1>
          <div className='form-group mt-2'>
            <label htmlFor='signup-username'>USER NAME</label> <br />
            <input
              type='text'
              id='signup-username'
              placeholder='Enter User Name'
              className='w-100'
              onChange={(e) =>
                setValues({ ...valus, username: e.target.value })
              }
              required
            />
          </div>
          <div className='form-group mt-2'>
            <label htmlFor='signup-email'>EMAIL</label> <br />
            <input
              type='email'
              id='signup-email'
              placeholder='Enter Email'
              className='w-100'
              onChange={(e) =>
                setValues({ ...valus, email: e.target.value })
              }
              required
            />
          </div>
          <div className='form-group mt-2'>
            <label htmlFor='signup-password'>PASSWORD</label> <br />
            <input
              type='password'
              id='signup-password'
              placeholder='Enter Password'
              className='w-100'
              onChange={(e) =>
                setValues({ ...valus, password: e.target.value })
              }
              required
            />
          </div>
          <button type='submit' className='btn btn-primary mt-3 w-100'>
            SignUp
          </button>
          <Link to='/login' className='btn btn-secondary mt-3 w-100'>
            Login
          </Link>
        </form>
      </div>
    </div>
  );
};

export default SignUp;
