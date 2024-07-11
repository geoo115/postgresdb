import { NavgridData } from "./NavgridData";
import { Component } from "react";
import "./Navgrid.css";

class NavGrid extends Component {
  // state = { clicked: false };
  // handleClick = () => {
  //   this.setState(!this.state.clicked);
  // };
  render() {
    return (
      <div className="nav-container">
        <h2 className="nav-title">Our Specialists</h2>
        <div>
          <div className="grid-container">
            {NavgridData.map((item, index) => {
              return (
                <div className="grid-item-container" key={index}>
                  <div className="grid-item" id={item.id}>
                    {item.image && <img src={item.image} alt={item.title} />}
                    <h3>{item.title}</h3>
                    <p>{item.text}</p>
                    <a href={item.url}>Find Specialist</a>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  }
}

export default NavGrid;

/* 
        <div className="grid-item" id="orange">
          1
        </div>
        <div className="grid-item" id="green">
          2
        </div>
        <div className="grid-item" id="orange">
          3
        </div>
        <div className="grid-item" id="green">
          4
        </div>
        <div className="grid-item" id="green">
          5
        </div>
        <div className="grid-item" id="orange">
          6
        </div>
        <div className="grid-item" id="green">
          7
        </div>
        <div className="grid-item" id="orange">
          8
        </div>
        <div className="grid-item" id="orange">
          9
        </div>
        <div className="grid-item" id="green">
          10
        </div>
        <div className="grid-item" id="orange">
          11
        </div>
        <div className="grid-item" id="green">
          12
        </div>
        <div className="grid-item" id="green">
          13
        </div>
        <div className="grid-item" id="orange">
          14
        </div>
        <div className="grid-item" id="green">
          15
        </div>
        <div className="grid-item" id="orange">
          16
        </div> 
      </div> 
    </div> */
