import "./Home.css";
import NavGrid from "./Navgrid";

const Home = () => {
  return (
    <div className="home-container">
      <div className="home-header">
        <div className="header-grid">
          <div className="header-item" id="orange-head">
            <h2>WHAT SET SQUARED GROUP CAN DO FOR YOU</h2>
            <p>
              Set Squared Group (SSG) offers businesses, and the general public,
              a considerably less complex way to source quality customer-focused
              financial advice and financial services from suitably qualified
              and trustworthy specialists.
            </p>
          </div>
          <div className="header-item" id="middle-img"></div>
          <img
            src="src/assets/homepage/ssg-logo.png"
            className="home-logo"
            alt="logo"
          />
          <div className="header-item" id="green-head">
            <p className="green-text">
              SSG have thoroughly vetted hand-picked specialist practitioners,
              enabling us to deliver everything to do with financial services,
              we facilitate easier access, at lower cost, for all UK residents,
              whether it be personal or business related.
            </p>
          </div>
        </div>
      </div>
      <div className="main-container">
        <NavGrid />
      </div>
    </div>
  );
};

export default Home;
