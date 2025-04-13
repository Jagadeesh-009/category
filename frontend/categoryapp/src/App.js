import React from 'react'
import { Route, Routes} from 'react-router-dom'
import LoginPage from './components/LoginPage'
import Signup from './components/Signup'
import Home from './components/Home'

import './App.css'


const App = () => {
   
    return (
        <div className='app'>
            <Routes>
                <Route path="/" element={<Home /> } />
                <Route exact path='/login' element={<LoginPage />} />
                <Route exact path='/signup' element={<Signup />} /> 
            </Routes>
        </div>
    )
}

export default App