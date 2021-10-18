import classNames from "classnames";
import Head from "next/head";
import Link from "next/link";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

export default function Devices(props) {
  return (
    <div className="flex flex-wrap">
      <div className="w-full md:w-1/2 xl:w-1/3 p-6">
        <div className="bg-gradient-to-b from-green-200 to-green-100 border-b-4 border-green-600 rounded-lg shadow-xl p-5">
          <div className="flex flex-row items-center">
            <div className="flex-shrink pr-4">
              <div className="rounded-full p-5 bg-green-600"><i className="fa fa-wallet fa-2x fa-inverse"></i></div>
            </div>
            <div className="flex-1 text-right md:text-center">
              <h5 className="font-bold uppercase text-gray-600">Total Devices</h5>
              <h3 className="font-bold text-3xl">3249 <span className="text-green-500"><i className="fas fa-caret-up"></i></span></h3>
            </div>
          </div>
        </div>
      </div>

      <div className="w-full md:w-1/2 xl:w-1/3 p-6">
        <div className="bg-gradient-to-b from-pink-200 to-pink-100 border-b-4 border-pink-500 rounded-lg shadow-xl p-5">
          <div className="flex flex-row items-center">
            <div className="flex-shrink pr-4">
              <div className="rounded-full p-5 bg-pink-600"><i className="fas fa-users fa-2x fa-inverse"></i></div>
            </div>
            <div className="flex-1 text-right md:text-center">
              <h5 className="font-bold uppercase text-gray-600">Acive Devices</h5>
              <h3 className="font-bold text-3xl">249 <span className="text-pink-500"><i className="fas fa-exchange-alt"></i></span></h3>
            </div>
          </div>
        </div>
      </div>

      <div className="w-full p-6">
        <div className="bg-white border-transparent rounded-lg shadow-xl">
          <div className="bg-gradient-to-b from-gray-300 to-gray-100 uppercase text-gray-800 border-b-2 border-gray-300 rounded-tl-lg rounded-tr-lg p-2">
            <h5 className="font-bold uppercase text-gray-600">Device Information</h5>
          </div>
          <div className="p-5">
            <table className="w-full p-5 text-gray-700">
              <thead>
                <tr>
                  <th className="text-left text-blue-900">ID</th>
                  <th className="text-left text-blue-900">Gateway ID</th>
                  <th className="text-left text-blue-900">MAC Address</th>
                  <th className="text-left text-blue-900">IP Address</th>
                  <th className="text-left text-blue-900">Status</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Obi Wan Kenobi</td>
                  <td>Obi Wan Kenobi</td>
                  <td>Light</td>
                  <td>Jedi</td>
                  <td>Jedi</td>
                </tr>
                <tr>
                  <td>Obi Wan Kenobi</td>
                  <td>Greedo</td>
                  <td>South</td>
                  <td>Scumbag</td>
                  <td>Jedi</td>
                </tr>
                <tr>
                  <td>Obi Wan Kenobi</td>
                  <td>Darth Vader</td>
                  <td>Dark</td>
                  <td>Sith</td>
                  <td>Jedi</td>
                </tr>
              </tbody>
            </table>
            <p className="py-2"><a href="#">See More issues...</a></p>
          </div>
        </div>
      </div>
    </div>
  );
}