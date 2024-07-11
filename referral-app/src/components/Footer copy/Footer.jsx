import React from "react";
import "./Footer.css";

const Footer = () => {
  return (
    <>
      <div className="footer">
        <div className="sb__footer section__padding">
          <div className="sb__footer-links">
            <div className="sb__footer-links-div">
              <h4>Company</h4>
              <a href="/home">
                <p>Homepage</p>
              </a>
              <a href="/how-it-works">
                <p>How It Works</p>
              </a>
              <a href="/about">
                <p>About Us</p>
              </a>
              <a href="/our-specialists">
                <p>Our Specialists</p>
              </a>
              <a href="/need-help">
                <p>Need Help</p>
              </a>
            </div>
            <div className="sb__footer-links-div">
              <h4>Documentation</h4>
              <a href="/privacy-policy">
                <p>Privacy Policy</p>
              </a>
              <a href="/terms-conditions">
                <p>Terms & Conditions</p>
              </a>
            </div>
            <div className="sb__footer-links-div">
              <h4>Socials</h4>
              <div className="socialmedia">
                <ul class="socials">
                  <li>
                    <a href="https://www.linkedin.com/company/set-squared-group">
                      <i class="fa-brands fa-linkedin"></i>
                    </a>
                  </li>
                  <li>
                    <a href="#">
                      <i class="fa-brands fa-facebook"></i>
                    </a>
                  </li>
                  <li>
                    <a href="#">
                      <i class="fa-brands fa-twitter"></i>
                    </a>
                  </li>
                </ul>
              </div>
            </div>
          </div>
          <hr></hr>
          <div className="sb__footer-below">
            <div className="sb__footer-copyright">
              <p>
                &copy; {new Date().getFullYear()} Set Squared. Designed by CHM
              </p>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Footer;
