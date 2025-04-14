import { Link, useNavigate } from 'react-router-dom'
import { useState } from 'react'
import axios from 'axios'
import './index.css'

const LoginPage = () => {
  const [values, setValues] = useState({
    username: '',
    password: '',
  })
  const [error, setError] = useState('')
  const navigate = useNavigate()

  axios.defaults.withCredentials = true

  const handleSubmit = (event) => {
    event.preventDefault()
    axios
      .post('http://localhost:8081/login', values)
      .then((res) => {
        if (res.data.status === 'success') {
          navigate('/')
        } else {
          setError(res.data.error)
          alert(res.data.error || 'Error logging in')
        }
      })
      .catch((err) => {
        console.error('Login error:', err)
        setError('Something went wrong. Please try again.')
      })
  }

  return (
    <div className='container d-flex align-items-center justify-content-center flex-column vh-100'>
      <div className='login-page'>
        <form className='login-form p-5' onSubmit={handleSubmit}>
          <h1 className='text-center mb-2'>LogIn</h1>
          {error && <p className='text-danger'>{error}</p>}
          <div className='form-group'>
            <label htmlFor='login-username'>USER NAME</label> <br />
            <input
              type='text'
              id='login-username'
              placeholder='Enter User Name'
              className='w-100'
              value={values.username}
              onChange={(e) =>
                setValues({ ...values, username: e.target.value })
              }
              required
            />
          </div>
          <div className='form-group mt-3'>
            <label htmlFor='login-password'>PASSWORD</label> <br />
            <input
              type='password'
              id='login-password'
              placeholder='Enter Password'
              className='w-100'
              value={values.password}
              onChange={(e) =>
                setValues({ ...values, password: e.target.value })
              }
              required
            />
          </div>
          <button type='submit' className='btn btn-primary mt-3 w-100'>
            LogIn
          </button>
          <Link to='/signup' className='btn btn-secondary mt-3 w-100'>
            SignUp
          </Link>
        </form>
      </div>
    </div>
  )
}

export default LoginPage
