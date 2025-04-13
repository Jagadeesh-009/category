import { Link } from 'react-router-dom';
import { FaSearch } from "react-icons/fa";
import { LuMessageSquareText } from "react-icons/lu";
import { MdOutlineAddAlert } from "react-icons/md";
import { SiCarto } from "react-icons/si";
import './index.css';

const Header = () => {
  const handleLogout = () => {
    // Clear session data or authentication token here if applicable
    // For example: localStorage.removeItem('authToken'); or sessionStorage.clear();

    // Redirect user to login page after logout
    window.location.href = '/login';
  };

  return (
    <header className="container-fluid bg-dark">
      <nav className="navbar navbar-expand-lg bg-dark navbar-dark px-3">
        <Link className="navbar-brand text-light" to="/"> <SiCarto className='text-light fs-3 fast-icon'/> Fastcart</Link>

        <button
          className="navbar-toggler"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#navbarContent"
          aria-controls="navbarContent"
          aria-expanded="false"
          aria-label="Toggle navigation"
        >
          <span className="navbar-toggler-icon"></span>
        </button>

        <div className="collapse navbar-collapse" id="navbarContent">
          {/* Search Bar */}
          <form className="form-search d-flex my-2 my-lg-0 ms-lg-5 ps-lg-5 w-25 w-lg-50">
            <input
              className="form-control me-2 text-light border-light"
              type="search"
              placeholder="Search..."
              aria-label="Search"
            />
            <button className="btn btn-outline-light" type="submit">
              <FaSearch />
            </button>
          </form>

          {/* Right-aligned items */}
          <ul className="navbar-nav ms-auto d-flex align-items-center gap-3 mt-3 mt-lg-0">
            <li className="nav-item">
              <Link className="nav-link text-light" to="/">
                <LuMessageSquareText className="fs-4" />
              </Link>
            </li>
            <li className="nav-item">
              <Link className="nav-link text-light" to="/">
                <MdOutlineAddAlert className="fs-4" />
              </Link>
            </li>
            <li className="nav-item d-flex align-items-center">
              <Link className="nav-link text-light d-flex align-items-center" to="/profile">
                <span className="name-icon me-2">J</span>
                <span>Jagadeesh</span>
              </Link>
            </li>
            {/* Logout button */}
            <li className="nav-item">
              <button className="btn btn-outline-light" onClick={handleLogout}>
                Logout
              </button>
            </li>
          </ul>
        </div>
      </nav>
    </header>
  );
};

export default Header;
