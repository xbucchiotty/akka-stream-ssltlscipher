import java.net.InetSocketAddress
import java.security.{KeyStore, SecureRandom}
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl._

import akka.actor.{ActorSystem, Props}
import akka.stream.io.SslTlsCipher.SessionNegotiation
import akka.stream.io.{SslTlsCipher, SslTlsCipherActor, StreamTcp}
import akka.stream.scaladsl._
import akka.stream.stage.{TerminationDirective, Directive, Context, PushPullStage}
import akka.stream.{FlowMaterializer, FlattenStrategy, MaterializerSettings}
import akka.testkit.TestProbe
import akka.util.ByteString
import com.typesafe.config.ConfigFactory
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.time.{Seconds, Span}
import org.scalatest.{BeforeAndAfterEach, FunSpec, ShouldMatchers}

import scala.concurrent._
import scala.concurrent.duration._
import scala.util.Random

//Think about adding -Djavax.net.debug=all to your test to watch SSL issue
class SslEngineSpec extends FunSpec with ShouldMatchers with ScalaFutures with BeforeAndAfterEach {

  import FlowOps._

  implicit val system: ActorSystem = ActorSystem("testing", ConfigFactory.empty())

  val settings = MaterializerSettings(system)

  implicit val defaultMaterializer = FlowMaterializer(settings)

  implicit val timeoutConfig = PatienceConfig(timeout = Span(5, Seconds))

  var testPort: Int = _

  describe("Client") {

    val serverJob: Flow[ByteString, ByteString] = replyToUpperCase.usingBytes

    def clientJob(msg: => String, sink: FoldSink[String, String]): Flow[ByteString, ByteString] = Flow(sink, source = send(msg)).usingBytes

    it("should send a message without tls and get reply back") {
      startServer(connection => connection.join(serverJob))

      val result = startClient { case (connection, replySink) =>
        connection.join(clientJob(msg = "hello", sink = replySink))
      }

      whenReady(result) {
        _ should be("HELLO")
      }
    }

    it("should send a message via tls and get reply back") {
      val sslContext = initSslContext()
      val clientCipher = sslEncryption("|  =   ")(createClientCipher(sslContext)) _
      val serverCipher = sslEncryption("   =  |")(createServerCipher(sslContext)) _

      startServer(connection => serverCipher(connection).join(serverJob))

      val result = startClient { case (connection, replySink) =>
        clientCipher(connection).join(clientJob(msg = "hello", sink = replySink))
      }

      whenReady(result) {
        _ should be("HELLO")
      }
    }

    it("should not be able to read encrypted text if no tls on server side") {
      val sslContext = initSslContext()
      val clientCipher = sslEncryption("|  =   ")(createClientCipher(sslContext)) _

      startServer(connection => connection.join(serverJob))

      val result = startClient { case (connection, replySink) =>
        clientCipher(connection).join(clientJob(msg = "hello", sink = replySink))
      }

      a[TimeoutException] should be thrownBy {
        Await.ready(result, atMost = timeoutConfig.timeout.totalNanos.nanos)
      }
    }

    it("should not be able to read encrypted text if no tls on client side") {
      val sslContext = initSslContext()
      val serverCipher = sslEncryption("   =  |")(createServerCipher(sslContext)) _

      startServer(connection => serverCipher(connection).join(serverJob))

      val result = startClient { case (connection, replySink) =>
        connection.join(clientJob(msg = "hello", sink = replySink))
      }

      a[TimeoutException] should be thrownBy {
        Await.ready(result, atMost = timeoutConfig.timeout.totalNanos.nanos)
      }
    }
  }

  def startServer(f: Flow[ByteString, ByteString] => RunnableFlow): Unit = {
    StreamTcp()
      .bind(new InetSocketAddress(testPort))
      .connections.foreach(connection => f(connection.flow).run())
  }

  def startClient(f: (Flow[ByteString, ByteString], FoldSink[String, String]) => RunnableFlow): Future[String] = {
    val outgoingConnections = StreamTcp().outgoingConnection(new InetSocketAddress(testPort)).flow
    val foldedReply: FoldSink[String, String] = FoldSink("")(_ ++ _)

    f(outgoingConnections, foldedReply).run().get(foldedReply)
  }


  def initSslContext(): SSLContext = {

    val password = "changeme"

    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    keyStore.load(getClass.getResourceAsStream("/keystore"), password.toCharArray)

    val trustStore = KeyStore.getInstance(KeyStore.getDefaultType)
    trustStore.load(getClass.getResourceAsStream("/truststore"), password.toCharArray)

    val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm)
    keyManagerFactory.init(keyStore, password.toCharArray)

    val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm)
    trustManagerFactory.init(trustStore)

    val context = SSLContext.getInstance("TLS")
    context.init(keyManagerFactory.getKeyManagers, trustManagerFactory.getTrustManagers, new SecureRandom)
    context
  }

  private val clientServerId = new AtomicInteger(0)

  def createClientCipher(context: SSLContext)(implicit system: ActorSystem): SslTlsCipher =
    createClientCipher(context, clientServerId.incrementAndGet())

  def createClientCipher(context: SSLContext, id: Int)(implicit system: ActorSystem): SslTlsCipher = {
    val engine = context.createSSLEngine
    engine.setEnabledCipherSuites(Array("TLS_RSA_WITH_AES_128_CBC_SHA"))
    engine.setUseClientMode(true)

    val requester = TestProbe()
    system.actorOf(Props(classOf[SslTlsCipherActor], requester.ref, SessionNegotiation(engine)), s"ssl-client-$id")
    requester.expectMsgType[SslTlsCipher]
  }

  def createServerCipher(context: SSLContext)(implicit system: ActorSystem): SslTlsCipher =
    createServerCipher(context, clientServerId.incrementAndGet())

  def createServerCipher(context: SSLContext, id: Int)(implicit system: ActorSystem): SslTlsCipher = {
    val engine = context.createSSLEngine
    engine.setEnabledCipherSuites(Array("TLS_RSA_WITH_AES_128_CBC_SHA"))
    engine.setUseClientMode(false)

    val requester = TestProbe()
    system.actorOf(Props(classOf[SslTlsCipherActor], requester.ref, SessionNegotiation(engine)), s"ssl-server-$id")
    requester.expectMsgType[SslTlsCipher]
  }

  override protected def beforeEach(): Unit = {
    testPort = Random.nextInt(1000) + 35823
  }

}

object FlowOps {
  def send(msg: => String): Source[String] = Source(() => List(msg).iterator)

  def replyToUpperCase: Flow[String, String] = Flow[String].map(_.toUpperCase)

  def byteEncoding: Flow[String, ByteString] =
    Flow[String].map(ByteString.fromString(_, "UTF-8"))

  def byteDecoding: Flow[ByteString, String] =
    Flow[ByteString].map(_.decodeString("UTF-8"))


  def sslEncryption(side: String)(cipher: SslTlsCipher)(plain: Flow[ByteString, ByteString])(implicit materializer: FlowMaterializer): Flow[ByteString, ByteString] = {
    def log(b: Broadcast[ByteString])(implicit builder: FlowGraphBuilder): Unit = {
      import akka.stream.scaladsl.FlowGraphImplicits._

      b ~> ForeachSink[ByteString] { bytes => println(s"$side: ${b.name.get} ==> ${bytes.decodeString("UTF-8").replaceAll("\n", "").replaceAll("\r", "")}")}
      b ~> OnCompleteSink[ByteString] { _ => println(s"$side: ${b.name.get} ==> completed")}
    }

    Flow() {
      implicit builder =>

        println(s"$side: SSL Encryption")

        import akka.stream.scaladsl.FlowGraphImplicits._

        plain.join(Flow(
          Sink(cipher.cipherTextInbound),
          Source(cipher.cipherTextOutbound).transform(() => new LoggingStage(side)("cipherTextOutbound"))
        )).run()

        //Plain text that needs to be encrypted to go outside on the wire
        //plainOutbound => PLAIN_TEXT_OUTBOUND |=> CIPHER_TEXT_OUTBOUND => plainConnection as sink
        val plainOutbound = UndefinedSource[ByteString]
        val b1 = Broadcast[ByteString]("plainOutbound")
        plainOutbound ~> b1 ~> Sink(cipher.plainTextOutbound)
        log(b1)


        //Plain text that needs to be decrypted to go inside the process
        //plainConnection as source => CIPHER_TEXT_INBOUND |=> SESSION => DATA => plainInbound => PROCESS
        val plainInbound = UndefinedSink[ByteString]
        Source(cipher.sessionInbound)
          .map(session => Source(session.data)).flatten(FlattenStrategy.concat).transform(() => new LoggingStage(side)("plainInbound")) ~> plainInbound

        (plainOutbound, plainInbound)
    }

  }

  implicit class StringFlow(val f: Flow[String, String]) extends AnyVal {
    def usingBytes: Flow[ByteString, ByteString] =
      byteDecoding via f via byteEncoding
  }

  class LoggingStage(side: String)(name: String) extends PushPullStage[ByteString, ByteString] {
    override def onPush(elem: ByteString, ctx: Context[ByteString]): Directive = {
      println(s"$side: $name ==> ${elem.decodeString("UTF-8").replaceAll("\n", "").replaceAll("\r", "")}")
      ctx.push(elem)
    }

    override def onPull(ctx: Context[ByteString]): Directive = {
      println(s"$side: $name pull")
      ctx.pull()
    }

    override def onUpstreamFinish(ctx: Context[ByteString]): TerminationDirective = {
      println(s"$side: $name onUpstreamFinish")
      super.onUpstreamFinish(ctx)
    }

    override def onDownstreamFinish(ctx: Context[ByteString]): TerminationDirective = {
      println(s"$side: $name onDownstreamFinish")
      super.onDownstreamFinish(ctx)
    }
  }


}
