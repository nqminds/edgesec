import React, {useState, useEffect} from "react";
import ReactDOM from "react-dom";
import Head from 'next/head'
import Image from 'next/image'
import dynamic from 'next/dynamic'
import styles from '../styles/Home.module.css'
const ForceGraph3D = dynamic(() => import('react-force-graph-3d'), {ssr: false});


function genRandomTree(N = 300, reverse = false) {
  return {
    nodes: [...Array(N).keys()].map(i => ({ id: i })),
      links: [...Array(N).keys()]
    .filter(id => id)
    .map(id => ({
      [reverse ? 'target' : 'source']: id,
      [reverse ? 'source' : 'target']: Math.round(Math.random() * (id-1))
    }))
  };
}

export default function Home() {
  const [tree, setTree] = useState({});
  useEffect(async () => {
    // Update the document title using the browser API
    setTree(genRandomTree());
    const reply = await fetch("http://essential-enigma.local:8080/nc/essential_enigma_HCG7/api/v1/Eth/distinct?column_name=Hash", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
  }, []);

  return (
    <div className={styles.container}>
      <main className={styles.main}>
        <ForceGraph3D graphData={tree}/>
      </main>
    </div>
  )
}
