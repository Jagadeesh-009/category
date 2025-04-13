import { useState, useEffect } from 'react'
import Header from '../Header'
import { AiOutlineHome } from "react-icons/ai";
import { GoListUnordered } from "react-icons/go";
import { IoPricetagOutline, IoPersonOutline, IoPersonAddOutline, IoSettingsOutline } from "react-icons/io5";
import { CiFolderOn } from "react-icons/ci";
import { HiOutlineDocumentReport } from "react-icons/hi";
import { RiCouponLine } from "react-icons/ri";
import { FaRegFolderOpen } from "react-icons/fa";
import { TbDeviceUnknown } from "react-icons/tb";
import { MdOutlineTipsAndUpdates } from "react-icons/md";
import './index.css'

const Home = () => {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const url = 'https://api.escuelajs.co/api/v1/products'
        const response = await fetch(url)
        if (!response.ok) {
          throw new Error('Failed to fetch')
        }
        const result = await response.json()
        setData(result)
        setLoading(false)
      } catch (e) {
        setError(e.message)
        setLoading(false)
      }
    }

    fetchData()
  }, [])

  return (
    <div className='container-fluid vh-100 p-0'>
      <Header />
      <div className='d-flex'>
        {/* Sidebar */}
        <div className='side-navbar p-4 pe-4'>
          <ul className='list-unstyled'>
            <li className='text-light btn'><AiOutlineHome className='fw-bold' /> Dashboard</li><br />
            <li className='text-light btn'><GoListUnordered /> Orders</li><br />
            <li className='text-light btn'><IoPricetagOutline /> Products</li><br />
            <li className='text-light btn'><CiFolderOn /> Categories</li><br />
            <li className='text-light btn'><IoPersonOutline /> Customers</li><br />
            <li className='text-light btn'><HiOutlineDocumentReport /> Reports</li><br />
            <li className='text-light btn'><RiCouponLine /> Coupons</li><br />
            <li className='text-light btn'><FaRegFolderOpen /> Index</li>
          </ul>
          <h4 className='text-light'>Other Information</h4>
          <ul className='list-unstyled'>
            <li className='text-light btn'><TbDeviceUnknown /> Knowledge Base</li><br />
            <li className='text-light btn'><MdOutlineTipsAndUpdates /> Product Updates</li>
          </ul>
          <h4 className='text-light'>Settings</h4>
          <ul className='list-unstyled'>
            <li className='text-light btn'><IoPersonAddOutline /> Personal Settings</li><br />
            <li className='text-light btn'><IoSettingsOutline /> Global Settings</li><br />
          </ul>
        </div>

        {/* Main Content */}
        <div className='main-content p-4 w-100 overflow-auto'>
          {loading ? (
            <p className='text-light'>Loading...</p>
          ) : error ? (
            <p className='text-danger'>Error: {error}</p>
          ) : (
            <>
              <div className='add d-flex justify-content-between align-items-center mb-3 '>
                <div><h1 className='category-heading'>Categories</h1></div>
                <div className=''>
                  <button className='btn btn-primary'> + Add Category</button>
                </div>
              </div>

              <ul className='list-unstyled d-flex flex-wrap gap-5 flex-basis-1'>
                {data.map(product => (
                  <li key={product.id}>
                    <div className="card" style={{ width: "15rem", height: "20rem" }}>
                      <img className="card-img-top" src={product.images[0]} height={200} alt={product.title} />
                      <div className="card-body">
                        <h5 className="card-title">{product.title}</h5>
                        <p className="card-text">{product.price} items</p>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default Home
