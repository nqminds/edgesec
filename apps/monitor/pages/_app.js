
import { useRouter } from "next/router";
import { config } from "@fortawesome/fontawesome-svg-core";
import "@fortawesome/fontawesome-svg-core/styles.css";
import "tailwindcss/tailwind.css";

config.autoAddCss = false

function MyApp({ Component, pageProps }) {
  const router = useRouter()
  const {page} = router.query;
  return <Component {...{page, ...pageProps}} />
}

export default MyApp
