// https://github.com/tailwindtoolbox/Admin-Template/blob/master/index.html
import Router from "next/router";
import { useEffect } from "react";
import { signIn, signOut, useSession } from "next-auth/client";
import classNames from "classnames";
import Head from "next/head";
import Link from "next/link";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faHome, faTabletAlt, faAngry, faChartLine } from "@fortawesome/free-solid-svg-icons";

import Gateways from "../components/Gateways";
import Devices from "../components/Devices";
import Alerts from "../components/Alerts";
import Traffic from "../components/Traffic";

function selectedMenuItem({icon, itemText, pageName}) {
  const aClassName = classNames(
    "block", "py-1", "md:py-3",
    "pl-1", "align-middle", "text-white",
    "no-underline", "hover:text-white", "border-b-2",
    {
      "border-gray-800": (itemText !== pageName),
      "border-blue-600": (itemText === pageName),
      "hover:border-purple-500": (itemText !== pageName),
    }
  );
  const faClassName = classNames({
    "text-blue-600": (itemText === pageName),
  });
  const spanClassName = classNames(
    "pb-1", "md:pb-0", "text-xs",
    "md:text-base", "block", "md:inline-block",
    "md:pl-2",
  {
    "text-gray-600": (itemText !== pageName),
    "text-white": (itemText === pageName),
    "md:text-gray-400": (itemText !== pageName),
    "md:text-white": (itemText === pageName),
  });
  return (
    <a className={aClassName}>
      <FontAwesomeIcon icon={icon} className={faClassName}/>
      <span className={spanClassName}>{itemText}</span>
    </a>
  );
}

function selectPage(name) {
  if (name === "Gateways") {
    return Gateways;
  } else if (name === "Devices") {
    return Devices;
  } else if (name === "Alerts") {
    return Alerts;
  } else if (name === "Traffic") {
    return Traffic;
  }

  return Gateways;
}

export default function Home(props) {
  const [ session, loading ] = useSession();

  const page = props.page || "Tasks";
  const navigatorMenuClass = classNames("block", "py-1", "md:py-3", "pl-1",
                                        "align-middle", "text-white", "no-underline",
                                        "hover:text-white", "border-b-2",
                                        "border-gray-800", "hover:border-purple-500");
  const mainClassName = classNames(
    "bg-gray-800", "font-sans", "leading-normal", "tracking-normal",
    {"mt-12": session,}
  );

  return (
    <main className={mainClassName}>
      <Head>
        <title>EDGESec Monitor</title>
        <link rel="icon" href="/favicon.ico" />
      </Head>
      {!session && 
      <>
        <div className="flex items-center justify-center h-screen">
          <a
            href={`/api/auth/signin`}
            className="bg-blue-500 hover:bg-blue-400 text-white font-bold py-2 px-4 border-b-4 border-blue-700 hover:border-blue-500 rounded"
            onClick={(e) => {
              e.preventDefault()
              signIn()
            }}
          >
            Sign in
          </a>
        </div>
      </>}
      {session && <>
        <nav className="bg-gray-800 pt-2 md:pt-1 pb-1 px-1 mt-0 h-auto fixed w-full z-20 top-0">
          <div className="flex flex-wrap items-center">
            <div className="flex flex-shrink md:w-1/3 justify-center md:justify-start text-white">
              <a href="#">
                  <span className="text-xl pl-2"><i className="em em-grinning"></i></span>
              </a>
            </div>

            <div className="flex flex-1 md:w-1/3 content-center justify-between md:justify-start text-white" >
            </div>

            <div className="flex w-full pt-2 content-center justify-between md:w-1/3 md:justify-end">
              <ul className="list-reset flex justify-between flex-1 md:flex-none items-center">
                  <li className="flex-1 md:flex-none md:mr-3">
                    <a
                      href={`/api/auth/signout`}
                      className="inline-block py-2 px-4 text-white no-underline"
                      onClick={(e) => {
                        e.preventDefault()
                        signOut()
                      }}
                    >
                      Sign out
                    </a>
                  </li>
              </ul>
            </div>
          </div>
        </nav>
        <div className="flex flex-col md:flex-row">
          <div className="bg-gray-800 shadow-xl h-16 fixed bottom-0 mt-12 md:relative md:h-screen z-10 w-full md:w-48">
            <div className="md:mt-12 md:w-48 md:fixed md:left-0 md:top-0 content-center md:content-start text-left justify-between">
              <ul className="list-reset flex flex-row md:flex-col py-0 md:py-3 px-1 md:px-2 text-center md:text-left">
                <li className="mr-3 flex-1">
                  <Link href={{pathname: "/", query: {page: "Gateways"}}}>
                    {selectedMenuItem({icon: faHome, itemText: "Gateways", pageName: page})}
                  </Link>
                </li>
                <li className="mr-3 flex-1">
                  <Link href={{pathname: "/", query: {page: "Devices"}}}>
                    {selectedMenuItem({icon: faTabletAlt, itemText: "Devices", pageName: page})}
                  </Link>
                </li>
                <li className="mr-3 flex-1">
                  <Link href={{pathname: "/", query: {page: "Alerts"}}}>
                    {selectedMenuItem({icon: faAngry, itemText: "Alerts", pageName: page})}
                  </Link>
                </li>
                <li className="mr-3 flex-1">
                  <Link href={{pathname: "/", query: {page: "Traffic"}}}>
                    {selectedMenuItem({icon: faChartLine, itemText: "Traffic", pageName: page})}
                  </Link>
                </li>
              </ul>
            </div>
          </div>

          <div className="main-content flex-1 bg-gray-100 mt-12 md:mt-2 pb-24 md:pb-5">
            <div className="bg-gray-800 pt-3">
              <div className="rounded-tl-3xl bg-gradient-to-r from-blue-900 to-gray-800 p-4 shadow text-2xl text-white">
                <h3 className="font-bold pl-2">{page}</h3>
              </div>
            </div>
            {selectPage(page)()}
          </div>
        </div>
      </>}
    </main>
  )
}
