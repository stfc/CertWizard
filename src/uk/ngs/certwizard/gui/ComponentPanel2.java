/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.certwizard.gui;
// ----------------------------------------------------------------------
// This code is developed as part of the Java CoG Kit project
// The terms of the license can be found at http://www.cogkit.org/license
// This message may not be removed or altered.
// ----------------------------------------------------------------------
//
// Changes made by by STFC: Copyright (c) 2009 Science and Technology Facilities Council.
// See included stfcLicence.LICENCE. Also found at: http://www.e-science.clrc.ac.uk/software/agreementform.htm
//


import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JPanel;

import org.globus.cog.gui.setup.components.CertificateAuthorityComponent;
import org.globus.cog.gui.setup.components.DateComponent;
//import org.globus.cog.gui.setup.components.IPAddressComponent;
import org.globus.cog.gui.setup.components.MyProxyComponent;
import org.globus.cog.gui.setup.components.DoActionsComponent;
import org.globus.cog.gui.setup.components.PolicyJarComponent;
import org.globus.cog.gui.setup.components.WelcomeComponent;
//import org.globus.cog.gui.setup.components.LocalProxyComponent;
//import org.globus.cog.gui.setup.components.PreviousSetupComponent;
//import org.globus.cog.gui.setup.components.PropertiesFileComponent;
import org.globus.cog.gui.setup.components.SetupComponent;
import org.globus.cog.gui.setup.components.UserCertificateComponent;
import org.globus.cog.gui.setup.components.VomsComponent;
import org.globus.cog.gui.setup.controls.ComponentListItem;
import org.globus.cog.gui.setup.events.ComponentStatusChangedEvent;
import org.globus.cog.gui.setup.events.ComponentStatusChangedListener;
import org.globus.cog.gui.setup.events.NavActionListener;
import org.globus.cog.gui.setup.events.NavEvent;
import org.globus.cog.gui.setup.panels.ListPanel;
import org.globus.cog.gui.setup.panels.NavPanel;
import org.globus.cog.gui.setup.panels.TitlePanel;
import org.globus.cog.gui.setup.util.ComponentLabelBridge;
import org.globus.cog.gui.setup.util.Constants;
import org.globus.cog.gui.setup.util.MyOverlayLayout;
//import org.globus.cog.gui.setup.util.MyProxyProperties3;
import org.globus.common.CoGProperties;
import org.globus.gsi.CertUtil;
import org.globus.cog.gui.setup.util.MyProxyProperties3;

/**
 *  The panel handling the components
 *
 * Custom event listening using custom ComponentStatusChangedEvents
 * and the EventListenerList property of each javax.swing.JComponent.
 * ===================================================================
 * 1) Each AbstractSetupComponent implements the SetupComponent interface which defines
 * 'addComponentStatusChangedListener(ComponentStatusChangedListener l)' method.
 * The default implementation of this method (in AbstractSetupComponent) adds the
 * given listener class (i.e. this class) to the AbstractSetupComponent internal
 * ListenerList property (which is a property of javax.swing.JComponent).
 *
 * 2) Since this class implements ComponentStatusChangedListener, it is
 * added to the ListenerList property of each AbstractSetupComponent (i.e. this
 * class is registered to be the ComponentStatusChangedListener for each
 * AbstractSetupComponent).
 *
 * 3) The ComponentStatusChanged events are fired manually as required from
 * within each SetupComponent using the method
 * 'AbstractSetupComponent.fireComponentStatusChangedEvent()'.
 * This method iterates the SetupComponents internal ListenerList property
 *
 *
 * It is the responsiblity of the class using the EventListenerList
 * to provide a type-safe API (preferably conforming to the JavaBeans spec)
 * and methods which dispatch event notification methods to appropriate
 * Event Listeners on the list.
 * @see <a href="http://java.sun.com/j2se/1.4.2/docs/api/javax/swing/event/EventListenerList.html">EventListener Java Spec</a>
 *
 */
public class ComponentPanel2 extends JPanel
        implements ComponentStatusChangedListener, NavActionListener {

    private LinkedList setupComponents;
    private ComponentLabelBridge visibleComponent = null;
    private ListPanel listPanel;
    private TitlePanel titlePanel;
    private NavPanel nav;
    private CoGProperties properties;

    public ComponentPanel2(TitlePanel titlePanel, ListPanel listPanel, NavPanel nav) {
        super();

        properties = CoGProperties.getDefault();

        this.titlePanel = titlePanel;
        this.listPanel = listPanel;
        this.nav = nav;

        // register this class as the NavEventListener for the given
        // NavPanel and ListPanel. This will invoke the navAction(e) method
        // in this class.
        nav.addNavEventListener(this);
        listPanel.addNavEventListener(this);

        setLayout(new MyOverlayLayout());
        setBorder(
                BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        setupComponents = new LinkedList();

        ComponentLabelBridge welcome = new ComponentLabelBridge(new WelcomeComponent());
        //ComponentLabelBridge policies = new ComponentLabelBridge(new PolicyJarComponent());
        //ComponentLabelBridge registration = new ComponentLabelBridge(new RegistrationComponent());
        //ComponentLabelBridge previousSetup =
        //        new ComponentLabelBridge(new PreviousSetupComponent(properties));
        ComponentLabelBridge userCertificate =
                new ComponentLabelBridge(new UserCertificateComponent(properties));
//        ComponentLabelBridge privateKey =
//                new ComponentLabelBridge(new PrivateKeyComponent(properties));
        ComponentLabelBridge certificateAuthority =
                new ComponentLabelBridge(new CertificateAuthorityComponent(properties));
//        ComponentLabelBridge localProxy =
//                new ComponentLabelBridge(new LocalProxyComponent(properties));
        //ComponentLabelBridge ipAddress =
        //        new ComponentLabelBridge(new IPAddressComponent(properties));
        ComponentLabelBridge date =
                new ComponentLabelBridge(new DateComponent(properties));
        //ComponentLabelBridge propertiesFile =
        //        new ComponentLabelBridge(new PropertiesFileComponent(properties));
        ComponentLabelBridge myproxyFile =
                new ComponentLabelBridge(new MyProxyComponent(properties));
        //ComponentLabelBridge proxyUpload =
         //       new ComponentLabelBridge(new DoActionsComponent(properties));
        ComponentLabelBridge vomsSetup =
                new ComponentLabelBridge(new VomsComponent(properties));


        // Add the welcome SetupComponent as the dependency for each of the other
        // SetupComponents
        // this Adds the welcome dependency for each component. The container should check the
        // dependencies (i.e. only welcome) and enable the component when the verify methods of the
        // dependencies are all <code>true</code> (thus, each component is enabled
        // as the welcome verify always returns true)
        //
        /*
        //registration.getSetupComponent().addDependency(license.getSetupComponent());
        //previousSetup.getSetupComponent().addDependency(welcome.getSetupComponent());
        //policies.getSetupComponent().addDependency(welcome.getSetupComponent());
        //userCertificate.getSetupComponent().addDependency(welcome.getSetupComponent());
//        privateKey.getSetupComponent().addDependency(welcome.getSetupComponent());
        certificateAuthority.getSetupComponent().addDependency(welcome.getSetupComponent());
//        localProxy.getSetupComponent().addDependency(welcome.getSetupComponent());
        //ipAddress.getSetupComponent().addDependency(welcome.getSetupComponent());
        date.getSetupComponent().addDependency(welcome.getSetupComponent());
        //propertiesFile.getSetupComponent().addDependency(welcome.getSetupComponent());
        myproxyFile.getSetupComponent().addDependency(welcome.getSetupComponent());
        //proxyUpload.getSetupComponent().addDependency(welcome.getSetupComponent());
        vomsSetup.getSetupComponent().addDependency(welcome.getSetupComponent());
        */

        // Add each SetupComponent to this (JPanel) container. The addSetupComponent()
        // The method also adds 'this' class to the SetupComponents EventListenerList property
        // (which is a list that is used to collect references to the the
        // SetupCompent's EventListeners). This classes 'componentStatusChanged'
        // method is called when the SetupCompoent fires status changes via
        // programatic calls.
        //
        addSetupComponent(welcome);
        //addSetupComponent(policies);
        //addSetupComponent(registration);
        //addSetupComponent(previousSetup);
        addSetupComponent(userCertificate);
        //       addSetupComponent(privateKey);
        addSetupComponent(certificateAuthority);
//        addSetupComponent(localProxy);
        //addSetupComponent(ipAddress);
        addSetupComponent(date);
        //addSetupComponent(propertiesFile);
        addSetupComponent(myproxyFile);
        addSetupComponent(vomsSetup);
        //addSetupComponent(proxyUpload);

        // below is dave started to look at not having to start from scratch
        // i.e. not having to start from setupComponent[0] if any setupComp
        // is wrong (esp the ip or date). Rather, would be much better to show a tick
        // or a cross for each component rather than neither a tick or cross.

        /*
         * setupComp title: [Welcome]
         * setupComp title: [1) Previous Setup]
         * setupComp title: [2) User Certificate]
         * setupComp title: [3) Private Key]
         * setupComp title: [4) Certificate Authorities]
         * setupComp title: [5) Local Proxy]
         * setupComp title: [6) IP Address]
         * setupComp title: [7) Date]
         * setupComp title: [8) Properties File]
         * setupComp title: [9) MyProxy Server]
         * setupComp title: [Do Actions:]
         */
        /*Constants.isCogEnabled = true;
        for(Object comp : setupComponents){
        SetupComponent setupComp =  ((ComponentLabelBridge)comp).getSetupComponent();
        //System.out.println("setupComp title: ["+setupComp.getTitle()+"]");
        }*/

        Constants.isCogEnabled = true;
        for (Object comp : setupComponents) {
            SetupComponent setupComp = ((ComponentLabelBridge) comp).getSetupComponent();
            //System.out.println("setupComp title: ["+setupComp.getTitle()+"]");
            if (!(setupComp instanceof MyProxyComponent) && !(setupComp instanceof PolicyJarComponent)) {
                if (!setupComp.verify()) {
                    Constants.isCogEnabled = false;
                    // break; // don't break, continue to verify
                }
            }
        }

        //check for MyProxy enabled
        //Constants.isMyProxyEnabled = new MyProxyProperties3().load();
        try{
           new MyProxyProperties3(MyProxyProperties3.DEFAULT_MYPROXY_PROPERTIES.getAbsolutePath());
           Constants.isMyProxyEnabled = true;
        } catch(Exception ex){
           Constants.isMyProxyEnabled = false;
        }

        Constants.isStart = true;
        for (int i = 0; i < setupComponents.size(); i++) {
            showComponent(i);
        }
        Constants.isStart = false;
        if (!Constants.isCogEnabled) {
            showComponent(0);
        }
        componentStatusChanged(null);



        // Iterate the setupComponents and verify each compoenent but break
        // after the first verification faliure (leaving the remaining
        // setupComponents un-verified).
        /*for (Object comp : setupComponents) {
        SetupComponent setupComp = ((ComponentLabelBridge) comp).getSetupComponent();
        System.out.println("setupComp title: [" + setupComp.getTitle() + "]");
        if (!(setupComp instanceof MyProxyComponent)) {
        //if(!setupComp.getTitle().startsWith("MyProxy") ){// <bad code
        // break after the first setupComp.verify() returns false.
        if (!setupComp.verify()) {
        Constants.isCogEnabled = false;
        break;
        }
        Constants.isCogEnabled = true;
        }
        }

        //check for MyProxy enabled
        Constants.isMyProxyEnabled = new MyProxyProperties3().load();
        // if all SetupComponents have been verified successfully,
        if (Constants.isCogEnabled) {
        Constants.isStart = true;
        // show each component
        for (int i = 0; i < 11; i++) { //setupComponents.size() -1, was 11
        showComponent(i);
        }
        // if myProxy properties have been loaded successfully show
        // the doActions page
        if (Constants.isMyProxyEnabled) {
        showComponent(10);
        }
        // set iStart to false (we are showing component 10)
        Constants.isStart = false;
        } else {
        // else always show the welcome component
        showComponent(0);
        }
        //
        componentStatusChanged(null);
         */
    }

    /**
     * Adds this class to the given ComponentLabelBridge's SetupComponent's
     * EventListenerList property (which is a List that is used to collect
     * all the references to the the SetupCompent's EventListeners). This
     * classes componentStatusChanged method is called when a SetupComponent
     * fires status changes.
     *
     * @param CLB
     */
    public void addSetupComponent(ComponentLabelBridge CLB) {
        setupComponents.add(CLB);
        JComponent JC = (JComponent) CLB.getSetupComponent().getVisualComponent();
        add(JC);
        listPanel.addItem(CLB.getComponentListItem());
        CLB.getSetupComponent().addComponentStatusChangedListener(this);
    }

    /**
     * Update the user certificate component only. 
     */
    public void updateUserCertificateComponent(){
        // force show of the user cert component
        this.showComponent(1);
        // force leave which will in-turn call verify.
        this.showComponent(0);
        this.showComponent(1);
        
        /*for (Object comp : setupComponents) {
            SetupComponent setupComp = ((ComponentLabelBridge) comp).getSetupComponent();
            if (setupComp instanceof UserCertificateComponent ) {
                setupComp.verify(); 
            }
        }*/
    }

    /**
     * This class listens for ComponentStatusChangedEvents.
     * Defined by ComponentStatusChangedListener interface.
     * Events are Fired manually by each SetupComponent.
     *
     * @param e
     */
    @Override
    public void componentStatusChanged(ComponentStatusChangedEvent e) {
        updateControls();
    }

    /**
     * Listen for NavEvents which will be fired by the buttons on the
     * NavPanel and ListPanel.
     *
     * @param e
     */
    @Override
    public void navAction(NavEvent e) {
        // This listener has been registed with the NavPanel and
        int Action = e.getNavAction();

        if (Action == NavEvent.Next) {
            nextComponent();
        } else if (Action == NavEvent.Prev) {
            prevComponent();
        } else if (Action == NavEvent.Jump) {
            showComponent(e.getJumpIndex());
        }
    }

    /**
     * Shows the component at the specified index, making sure the active
     * component is de-activated nicely by first invoking the current visible
     * setupComponents leave method.
     *
     *@param  index  Description of the Parameter
     */
    private void showComponent(int index) {
        //System.out.println("showComponent: " + index);
        if ((index > setupComponents.size()) || (index < 0)) {
            return;
        }

        ComponentLabelBridge crtBridge = (ComponentLabelBridge) setupComponents.get(index);
        SetupComponent crtComp = crtBridge.getSetupComponent();

        if (visibleComponent != null) {
            // call SetupComponent.leave() which calls its verify() method
            // and sets SC.completed depending on whether all of the SCs
            // dependencies can be verified, and if itself can be verified.
            if (!visibleComponent.getSetupComponent().leave()) {
                // SetupComponent leave() method has returned false so return.
                // Note, the SetupComponent's leave method invokes its
                // verify() method, and if the component cannot verify itself,
                // then a dialog is presented to the user so that they can
                // confirm that the SetupComponent has failed verification
                // (confirm bogus settings). If the user requests they continue,
                // then the leave() method will return true. If the user
                // chooses not to continue, then leave() will return false and
                // we stay at the current visibleComponent.
                return;
            }
            // ok, we are moving onto the requested component, thus
            // inactivate the current visible component.
            visibleComponent.getComponentListItem().setActive(false);
        }

        //System.out.println("pre enterComponent: " + index);
        //if(callEnter)
        crtComp.enter(); // simply sets the component as visible to true
        visibleComponent = crtBridge; // This is the only place where visibleComponent is set.
        visibleComponent.getComponentListItem().setActive(true);
        updateControls();
    }

    /**
     * a) Iterate each SC and call its verify() method if SC.completed == true
     * (the SC.completed property is only set when leaving the SC).
     * If SC can be verfied ok, then set its corresponding state flag accordingly
     * on the left hand list panel.
     *
     * b) set the nav panel buttons (previous and next) to be enabled or not.
     * c) set the text of the title label.
     */
    private void updateControls() {
        //System.out.println("updatecontrols: ");

        // iterate each SetupComponent
        for (int i = 0; i < setupComponents.size(); i++) {
            // if setupcomponent[i] is visibileComponent set its state to StateNone
            if (setupComponents.get(i) == visibleComponent) {
                visibleComponent.getComponentListItem().setState(ComponentListItem.StateNone);
                // this line to ensure any methods in verify() are carried out
                visibleComponent.getSetupComponent().verify();
                continue; // force next iteration
            }

            SetupComponent SC = ((ComponentLabelBridge) setupComponents.get(i)).getSetupComponent();
            LinkedList Deps = SC.getDependencies();
            boolean DependOk = true;

            // Iterate each of SC's dependencies and
            // verfiy each (should always verify since welcome dependency
            // is the only used SetupComponent used as a dep).
            for (int j = 0; j < Deps.size(); j++) {
                SetupComponent Dep = (SetupComponent) Deps.get(j);
                if (!Dep.verify()) {
                    DependOk = false;
                    break;
                }
            }

            // verify SC itself and set its componentListItem accordingly
            ComponentListItem LI = ((ComponentLabelBridge) setupComponents.get(i)).getComponentListItem();
            if (DependOk) {
                if (SC.completed()) {
                    if (SC.verify()) {
                        LI.setState(ComponentListItem.StateOk);
                    } else {
                        LI.setState(ComponentListItem.StateFailed);
                    }
                } else {
                    LI.setState(ComponentListItem.StateNone);
                }
            } else {
                LI.setState(ComponentListItem.StateDisabled);
            }
        }

        // This bit corrects the above for the policy jar page.
        ComponentLabelBridge policyBridge = (ComponentLabelBridge) setupComponents.get(1);
        SetupComponent policyComponent = policyBridge.getSetupComponent();
        if (!policyComponent.verify()) {
            policyBridge.getComponentListItem().setState(ComponentListItem.StateWarning);
        }
        // This bit corrects the above for the Welcome component and the
        // Do Actions component.  They always want the same icons as they are
        // not really part of the setup.  This assumes (I think reasonably) that
        // they will remain the first and last components in the list.
        ComponentListItem welcomeComponent = ((ComponentLabelBridge) setupComponents.get(0)).getComponentListItem();
        welcomeComponent.setState(ComponentListItem.StateWelcome);
        welcomeComponent = ((ComponentLabelBridge) setupComponents.get(setupComponents.size() - 1)).getComponentListItem();
        welcomeComponent.setState(ComponentListItem.StateDA);


        // set the next and previous buttons on the nav panel accordingly.
        nav.setNextEnabled(nextAvailable());
        nav.setPrevEnabled(prevAvailable());
        if (visibleComponent.getSetupComponent().canFinish()) {
            //nav.setFinishEnabled(true);
            nav.setCancelEnabled(false);
        } else {
            //nav.setFinishEnabled(false);
        }

        // update the status icon (method below)
        this.setupImage();

        // set the title of visible component
        titlePanel.setTitle(visibleComponent.getSetupComponent().getTitle());
        titlePanel.setHelp(
                visibleComponent.getSetupComponent().getHelpFile());
    }

    private void nextComponent() {
        if (visibleComponent == null) {
            showComponent(0);
            return;
        }
        int next = getNext(getVisibleComponentIndex());
        if (next != -1) {
            showComponent(next);
        }
        return;
    }

    private void prevComponent() {
        if (visibleComponent == null) {
            showComponent(0);
            return;
        }
        int prev = getPrev(getVisibleComponentIndex());
        if (prev != -1) {
            showComponent(prev);
        }
        return;
    }

    private boolean nextAvailable() {
        if (visibleComponent == null) {
            return true;
        }
        if (getNext(getVisibleComponentIndex()) != -1) {
            return true;
        }
        return false;
    }

    private boolean prevAvailable() {
        if (visibleComponent == null) {
            return true;
        }
        if (getPrev(getVisibleComponentIndex()) != -1) {
            return true;
        }
        return false;
    }

    private int getVisibleComponentIndex() {
        for (int i = 0; i < setupComponents.size(); i++) {
            if (setupComponents.get(i) == visibleComponent) {
                return i;
            }
        }
        return -1;
    }

    public SetupComponent getVisibleComponent() {
        return visibleComponent.getSetupComponent();
    }

    private int getPrev(int index) {
        for (int j = index - 1; j >= 0; j--) {
            ComponentLabelBridge CLB = (ComponentLabelBridge) setupComponents.get(j);
            ComponentListItem CLI = CLB.getComponentListItem();

            if (CLI.getState() != ComponentListItem.StateDisabled) {
                return j;
            }
        }
        return -1;
    }

    private int getNext(int index) {
        for (int j = index + 1; j < setupComponents.size(); j++) {
            ComponentLabelBridge CLB = (ComponentLabelBridge) setupComponents.get(j);
            ComponentListItem CLI = CLB.getComponentListItem();

            if (CLI.getState() != ComponentListItem.StateDisabled) {
                return j;
            }
        }
        return -1;
    }

    // method which finds the time left until certificate expiry, and passes it
    // to the setupImage() method in NavPanel
    private void setupImage() {
        //proxy info
        String file = CoGProperties.getDefault().getUserCertFile();
        X509Certificate cert = null;
        Date expiry = null;
        Date current = new Date();

        try {
            cert = CertUtil.loadCertificate(file);
            expiry = cert.getNotAfter();
            long expTime = expiry.getTime();
            long curTime = current.getTime();
            long timeLeft = expTime - curTime;
            nav.setupImage(timeLeft);
            // this is the most direct method of getting to the Do Actions component
            // that I can finds
            //setupComponents.get(setupComponents.size() - 1).getCredStatus().setCertDetails(timeLeft);
        } catch (Exception ex) {
            // there is effectively no chance that 0 will get passed otherwise
            nav.setupImage(0L);  // handle this as a separate case
        }
    }
    /**
     * next three functions don't seem to be used.
     */

    /* public void addComponentStatusChangedListener(ComponentStatusChangedListener CSCL) {
    System.out.println("this is called dave 1");
    listenerList.add(ComponentStatusChangedListener.class, CSCL);
    }

    public void fireComponentStatusChangedEvent(ComponentStatusChangedEvent e) {
    System.out.println("this is called dave 2");
    Object[] listeners = listenerList.getListenerList();

    for (int i = listeners.length - 2; i >= 0; i -= 2) {
    if (listeners[i] == ComponentStatusChangedListener.class) {
    ((ComponentStatusChangedListener) listeners[i + 1]).componentStatusChanged(e);
    }
    }

    }

    public void showComponent(String title) {
    Iterator components = setupComponents.listIterator();

    while (components.hasNext()) {
    ComponentLabelBridge crtBridge = (ComponentLabelBridge) components.next();
    SetupComponent crtComp = crtBridge.getSetupComponent();

    if (crtComp.getTitle().compareTo(title) == 0) {
    if (visibleComponent != null) {
    if (!visibleComponent.getSetupComponent().leave()) {
    return;
    }
    }
    crtComp.enter();
    visibleComponent = crtBridge;
    break;
    }
    }
    }*/
}
