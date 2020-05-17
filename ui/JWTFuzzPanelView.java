/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.fuzz.jwtfuzzer.ui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import java.util.regex.Matcher;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import org.apache.commons.configuration.FileConfiguration;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.jwtfuzzer.JWTHolder;
import org.zaproxy.zap.extension.fuzz.jwtfuzzer.messagelocations.JWTMessageLocation;
import org.zaproxy.zap.extension.fuzz.jwtfuzzer.ui.utils.JWTConstants;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent.ViewComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestStringHttpPanelViewModel;
import org.zaproxy.zap.model.HttpMessageLocation.Location;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlight;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlighter;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlightsManager;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducer;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListener;
import org.zaproxy.zap.view.messagelocation.MessageLocationProducerFocusListenerAdapter;
import org.zaproxy.zap.view.messagelocation.TextMessageLocationHighlightsManager;

/** @author preetkaran20@gmail.com KSASAN */
public class JWTFuzzPanelView
        implements HttpPanelView, MessageLocationProducer, MessageLocationHighlighter {

    private static final Logger LOGGER = Logger.getLogger(JWTFuzzPanelView.class);
    private static final String HEADER_COMPONENT_LABEL = "Header";
    private static final String PAYLOAD_COMPONENT_LABEL = "Payload";

    private MessageLocationProducerFocusListenerAdapter focusListenerAdapter;
    private JPanel contentPane;
    private JComboBox<String> jwtComboBox;
    private JComboBox<String> jwtComponentType;
    private JComboBox<String> jwtComponentJsonKeysComboBox;

    private Vector<String> jwtComboBoxModel = new Vector<String>(Arrays.asList("--Select--"));
    private HttpMessage message;
    private Map<String, String> comboBoxKeyAndJwtMap = new HashMap<>();
    private Map<JWTMessageLocation, List<Component>> jwtMessageLocationAndRelatedComponentsMap =
            new HashMap<>();
    private ViewComponent viewComponent;

    public JWTFuzzPanelView() {
        this(null);
    }

    public JWTFuzzPanelView(ViewComponent viewComponent) {
        contentPane = new JPanel();
        init();
        this.viewComponent = viewComponent;
    }

    private void init() {
        generalSettingsSection();
    }

    private void generalSettingsSection() {
        jwtComboBox = new JComboBox<String>(this.jwtComboBoxModel);
        jwtComponentType = new JComboBox<String>();
        jwtComponentJsonKeysComboBox = new JComboBox<String>();
        jwtComboBox.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent actionEvent) {
                        if (jwtComboBox.getSelectedIndex() > 0) {
                            String selectedItem =
                                    comboBoxKeyAndJwtMap.get(
                                            jwtComboBox.getSelectedItem().toString());
                            try {
                                JWTHolder jwtHolder = JWTHolder.parseJWTToken(selectedItem);
                                jwtComponentType.removeAllItems();
                                ;
                                jwtComponentType.addItem(HEADER_COMPONENT_LABEL);
                                if (isValidJson(jwtHolder.getPayload())) {
                                    jwtComponentType.addItem(PAYLOAD_COMPONENT_LABEL);
                                }
                                jwtComponentType.setSelectedIndex(0);
                                contentPane.add(jwtComponentType);
                                contentPane.add(jwtComponentJsonKeysComboBox);
                                String jwtComponentValue = jwtHolder.getHeader();
                                if (jwtComponentType.getSelectedIndex() == 1) {
                                    jwtComponentValue = jwtHolder.getPayload();
                                }
                                JSONObject jsonObject = new JSONObject(jwtComponentValue);
                                Vector<String> keys = new Vector<>();
                                keys.addAll(jsonObject.keySet());
                                jwtComponentJsonKeysComboBox.removeAllItems();
                                for (String key : keys) {
                                    jwtComponentJsonKeysComboBox.addItem(key);
                                }
                                jwtComponentJsonKeysComboBox.setSelectedIndex(0);
                                contentPane.revalidate();
                                jwtComponentType.addActionListener(
                                        new ActionListener() {

                                            @Override
                                            public void actionPerformed(ActionEvent e) {
                                                String handle = jwtHolder.getHeader();
                                                if (jwtComponentType.getSelectedIndex() == 1) {
                                                    handle = jwtHolder.getPayload();
                                                }
                                                JSONObject jsonObject = new JSONObject(handle);
                                                Vector<String> keys = new Vector<>();
                                                keys.addAll(jsonObject.keySet());
                                                jwtComponentJsonKeysComboBox.removeAllItems();
                                                for (String key : keys) {
                                                    jwtComponentJsonKeysComboBox.addItem(key);
                                                }
                                                jwtComponentJsonKeysComboBox.setSelectedIndex(0);
                                                contentPane.revalidate();
                                            }
                                        });
                            } catch (Exception e) {
                                LOGGER.error("Error Occurred: ", e);
                            }
                        } else {
                            if (jwtComponentJsonKeysComboBox != null) {
                                jwtComponentJsonKeysComboBox.removeAllItems();
                                contentPane.remove(jwtComponentJsonKeysComboBox);
                            }

                            if (jwtComponentType != null) {
                                jwtComponentType.removeAllItems();
                                contentPane.remove(jwtComponentType);
                            }
                        }
                        contentPane.revalidate();
                    }
                });
        contentPane.add(jwtComboBox);
        contentPane.revalidate();
    }

    @Override
    public String getName() {
        return "JWT";
    }

    @Override
    public String getCaptionName() {
        return "JWT";
    }

    @Override
    public String getTargetViewName() {
        return null;
    }

    @Override
    public int getPosition() {
        return 0;
    }

    @Override
    public JComponent getPane() {
        return contentPane;
    }

    @Override
    public void setSelected(boolean selected) {
        if (selected) {
            this.contentPane.requestFocusInWindow();
        }
    }

    @Override
    public void save() {}

    @Override
    public HttpPanelViewModel getModel() {
        return new RequestStringHttpPanelViewModel();
    }

    private boolean isValidJson(String value) {
        try {
            new JSONObject(value);
        } catch (JSONException ex) {
            return false;
        }
        return true;
    }

    public void populateJWTTokens(String httpMessageString) {
        Matcher matcher = JWTConstants.JWT_TOKEN_REGEX_FIND_PATTERN.matcher(httpMessageString);
        while (matcher.find()) {
            String jwtToken = matcher.group().trim();
            String key = jwtToken;
            try {
                JWTHolder jwtHolder = JWTHolder.parseJWTToken(key);
                // As Header of JWT is always JSON so header component should be a valid JSON Object
                // for the token to qualify
                // as valid JWT.
                if (isValidJson(jwtHolder.getHeader())) {
                    if (key.length() > 30) {
                        key = jwtToken.substring(0, 30);
                    }
                    comboBoxKeyAndJwtMap.put(key.concat("..."), jwtToken);
                }
            } catch (Exception e) {
                LOGGER.debug("Not a valid JWT Token", e);
            }
        }
    }

    public void setMessage(Message message) {
        if (viewComponent == ViewComponent.HEADER) {
            this.populateJWTTokens(this.message.getRequestHeader().toString());
        } else if (viewComponent == ViewComponent.BODY) {
            this.populateJWTTokens(this.message.getRequestBody().toString());
        } else {
            this.populateJWTTokens(this.message.getRequestHeader().toString());
            this.populateJWTTokens(this.message.getRequestBody().toString());
        }
        Set<String> jwtTokens = this.comboBoxKeyAndJwtMap.keySet();
        for (String jwtToken : jwtTokens) {
            jwtComboBoxModel.addElement(jwtToken);
        }
        this.contentPane.revalidate();
    }

    @Override
    public boolean isEnabled(Message message) {
        if (message != null) {
            this.message = (HttpMessage) message;
            setMessage(message);
            if (jwtComboBox.getItemCount() > 1) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean hasChanged() {
        return true;
    }

    @Override
    public boolean isEditable() {
        return true;
    }

    @Override
    public void setEditable(boolean editable) {}

    @Override
    public void setParentConfigurationKey(String configurationKey) {}

    @Override
    public void loadConfiguration(FileConfiguration configuration) {}

    @Override
    public void saveConfiguration(FileConfiguration configuration) {}

    @Override
    public MessageLocation getSelection() {
        Location location;
        String jwt = comboBoxKeyAndJwtMap.get(jwtComboBox.getSelectedItem().toString());
        String jwtComponentJsonKey = this.jwtComponentJsonKeysComboBox.getSelectedItem().toString();
        boolean isHeaderComponent =
                this.jwtComponentType.getSelectedItem().equals(HEADER_COMPONENT_LABEL);
        int startIndex = this.message.getRequestHeader().toString().indexOf(jwt);
        if (startIndex >= 0) {
            location = Location.REQUEST_HEADER;
        } else {
            location = Location.REQUEST_BODY;
        }

        if (startIndex < 0) {
            startIndex = this.message.getRequestBody().toString().indexOf(jwt);
        }
        JWTMessageLocation jwtMessageLocation =
                new JWTMessageLocation(
                        location,
                        startIndex,
                        startIndex + jwt.length() - 1,
                        jwt,
                        jwtComponentJsonKey,
                        isHeaderComponent);
        List<Component> components =
                Arrays.asList(
                        this.jwtComboBox, this.jwtComponentType, this.jwtComponentJsonKeysComboBox);
        this.jwtMessageLocationAndRelatedComponentsMap.put(jwtMessageLocation, components);
        return jwtMessageLocation;
    }

    @Override
    public void addFocusListener(MessageLocationProducerFocusListener focusListener) {
        getFocusListenerAdapter().addFocusListener(focusListener);
    }

    @Override
    public void removeFocusListener(MessageLocationProducerFocusListener focusListener) {
        getFocusListenerAdapter().removeFocusListener(focusListener);

        if (!getFocusListenerAdapter().hasFocusListeners()) {
            getPane().removeFocusListener(focusListenerAdapter);
            focusListenerAdapter = null;
        }
    }

    private MessageLocationProducerFocusListenerAdapter getFocusListenerAdapter() {
        if (focusListenerAdapter == null) {
            focusListenerAdapter = new MessageLocationProducerFocusListenerAdapter(this);
            getPane().addFocusListener(focusListenerAdapter);
        }
        return focusListenerAdapter;
    }

    @Override
    public MessageLocationHighlight highlight(MessageLocation location) {
        this.jwtMessageLocationAndRelatedComponentsMap
                .get(location)
                .forEach((component) -> component.setEnabled(false));
        generalSettingsSection();
        return null;
    }

    @Override
    public MessageLocationHighlight highlight(
            MessageLocation location, MessageLocationHighlight highlight) {
        this.jwtMessageLocationAndRelatedComponentsMap
                .get(location)
                .forEach((component) -> component.setEnabled(false));
        generalSettingsSection();
        return highlight;
    }

    @Override
    public void removeHighlight(
            MessageLocation location, MessageLocationHighlight highlightReference) {
        this.jwtMessageLocationAndRelatedComponentsMap
                .get(location)
                .forEach((component) -> contentPane.remove(component));
        contentPane.revalidate();
        this.jwtMessageLocationAndRelatedComponentsMap.remove((JWTMessageLocation) location);
    }

    @Override
    public Class<? extends MessageLocation> getMessageLocationClass() {
        return JWTMessageLocation.class;
    }

    @Override
    public MessageLocationHighlightsManager create() {
        return new TextMessageLocationHighlightsManager();
    }

    @Override
    public boolean supports(MessageLocation location) {
        return location instanceof JWTMessageLocation;
    }

    @Override
    public boolean supports(Class<? extends MessageLocation> classLocation) {
        return JWTMessageLocation.class.isAssignableFrom(classLocation);
    }
}
