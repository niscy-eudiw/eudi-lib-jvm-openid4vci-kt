package eu.europa.ec.eudi.openid4vci.examples

import org.openqa.selenium.chrome.ChromeDriver
import java.io.Closeable

interface ResourceWrapper<R> : Closeable {
    val resource: R

    companion object {
        operator fun <R> invoke(create: () -> R, close: R.() -> Unit): ResourceWrapper<R> =
            object : ResourceWrapper<R> {
                override val resource: R
                    get() = create.invoke()

                override fun close() {
                    resource.close()
                }
            }

        fun chromeDriver(create: (()->ChromeDriver)? = null): ResourceWrapper<ChromeDriver> =
            invoke(create = create ?: {ChromeDriver()}, close = ChromeDriver::quit)
    }
}