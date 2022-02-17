import classNames from "classnames";
import Head from "next/head";
import Link from "next/link";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

export default function Traffic(props) {
  return (
    <div className="flex flex-wrap">
      <div className="w-full p-6">
        <div className="bg-white border-transparent rounded-lg shadow-xl">
          <div className="bg-gradient-to-b from-gray-300 to-gray-100 uppercase text-gray-800 border-b-2 border-gray-300 rounded-tl-lg rounded-tr-lg p-2">
            <h5 className="font-bold uppercase text-gray-600">Traffic Information</h5>
          </div>
          <div className="p-5">
            <table className="w-full p-5 text-gray-700">
              <thead>
                <tr>
                  <th className="text-left text-blue-900">Gateway ID</th>
                  <th className="text-left text-blue-900">Hostname</th>
                  <th className="text-left text-blue-900">MAC</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Obi Wan Kenobi</td>
                  <td>Light</td>
                  <td>Jedi</td>
                </tr>
                <tr>
                  <td>Greedo</td>
                  <td>South</td>
                  <td>Scumbag</td>
                </tr>
                <tr>
                  <td>Darth Vader</td>
                  <td>Dark</td>
                  <td>Sith</td>
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